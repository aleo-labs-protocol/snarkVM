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

impl<N: Network> Parser for Future<N> {
    /// Parses a string into a future value.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the future from the string.
        Self::parse_internal(string, 0)
    }
}

impl<N: Network> Future<N> {
    /// Parses an array of future arguments: `[arg_0, ..., arg_1]`, while tracking the depth of the data.
    fn parse_arguments(string: &str, depth: usize) -> ParserResult<'_, Vec<Argument<N>>> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "[" from the string.
        let (string, _) = tag("[")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the members.
        let (string, arguments) = separated_list0(
            pair(pair(Sanitizer::parse_whitespaces, tag(",")), Sanitizer::parse),
            alt((
                map(|input| Self::parse_internal(input, depth + 1), Argument::Future),
                map(DynamicFuture::parse, Argument::DynamicFuture),
                map(Plaintext::parse, Argument::Plaintext),
            )),
        )(string)?;
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the ']' from the string.
        let (string, _) = tag("]")(string)?;
        // Output the plaintext.
        Ok((string, arguments))
    }

    /// Parses a string into a future value, while tracking the depth of the data.
    #[inline]
    fn parse_internal(string: &str, depth: usize) -> ParserResult<'_, Self> {
        // Ensure that the depth is within the maximum limit.
        // Note: `N::MAX_DATA_DEPTH` is an upper bound on the number of nested futures.
        //  The true maximum is defined by `Transaction::<N>::MAX_TRANSITIONS`, however, that object is not accessible in this crate.
        //  In practice, `MAX_DATA_DEPTH` is 32, while `MAX_TRANSITIONS` is 31.
        if depth > N::MAX_DATA_DEPTH {
            return map_res(take(0usize), |_| {
                Err(error(format!("Found a future that exceeds maximum data depth ({})", N::MAX_DATA_DEPTH)))
            })(string);
        }
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "{" from the string.
        let (string, _) = tag("{")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "program_id" from the string.
        let (string, _) = tag("program_id")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the program ID from the string.
        let (string, program_id) = ProgramID::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "," from the string.
        let (string, _) = tag(",")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "function_name" from the string.
        let (string, _) = tag("function_name")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the function name from the string.
        let (string, function_name) = Identifier::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "," from the string.
        let (string, _) = tag(",")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "arguments" from the string.
        let (string, _) = tag("arguments")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the arguments from the string.
        let (string, arguments) = Self::parse_arguments(string, depth)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "}" from the string.
        let (string, _) = tag("}")(string)?;

        Ok((string, Self::new(program_id, function_name, arguments)))
    }
}

impl<N: Network> FromStr for Future<N> {
    type Err = Error;

    /// Returns a future from a string literal.
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

impl<N: Network> Debug for Future<N> {
    /// Prints the future as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Future<N> {
    /// Prints the future as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.fmt_internal(f, 0)
    }
}

impl<N: Network> Future<N> {
    /// Prints the future with the given indentation depth.
    fn fmt_internal(&self, f: &mut Formatter, depth: usize) -> fmt::Result {
        /// The number of spaces to indent.
        const INDENT: usize = 2;

        // Print the opening brace.
        write!(f, "{{")?;

        // Print the program ID.
        write!(
            f,
            "\n{:indent$}program_id: {program_id},",
            "",
            indent = (depth + 1) * INDENT,
            program_id = self.program_id()
        )?;
        // Print the function name.
        write!(
            f,
            "\n{:indent$}function_name: {function_name},",
            "",
            indent = (depth + 1) * INDENT,
            function_name = self.function_name()
        )?;
        // Print the arguments.
        // If the arguments are empty, print an empty array.
        if self.arguments.is_empty() {
            write!(f, "\n{:indent$}arguments: []", "", indent = (depth + 1) * INDENT)?;
        } else {
            write!(f, "\n{:indent$}arguments: [", "", indent = (depth + 1) * INDENT)?;
            self.arguments.iter().enumerate().try_for_each(|(i, argument)| {
                match argument {
                    Argument::Plaintext(plaintext) => match i == self.arguments.len() - 1 {
                        true => {
                            // Print the last argument without a comma.
                            write!(f, "\n{:indent$}{plaintext}", "", indent = (depth + 2) * INDENT)
                        }
                        // Print the argument with a comma.
                        false => {
                            write!(f, "\n{:indent$}{plaintext},", "", indent = (depth + 2) * INDENT)
                        }
                    },
                    Argument::Future(future) => {
                        // Print a newline.
                        write!(f, "\n{:indent$}", "", indent = (depth + 2) * INDENT)?;
                        // Print the argument.
                        future.fmt_internal(f, depth + 2)?;
                        // Print the closing brace.
                        match i == self.arguments.len() - 1 {
                            // Print the last member without a comma.
                            true => write!(f, "\n{:indent$}", "", indent = (depth + 1) * INDENT),
                            // Print the member with a comma.
                            false => write!(f, ","),
                        }
                    }
                    Argument::DynamicFuture(dynamic_future) => {
                        match i == self.arguments.len() - 1 {
                            true => {
                                // Print the last argument without a comma.
                                write!(f, "\n{:indent$}{dynamic_future}", "", indent = (depth + 2) * INDENT)
                            }
                            // Print the argument with a comma.
                            false => write!(f, "\n{:indent$}{dynamic_future},", "", indent = (depth + 2) * INDENT),
                        }
                    }
                }
            })?;
            // Print the closing bracket.
            write!(f, "\n{:indent$}]", "", indent = (depth + 1) * INDENT)?;
        }

        // Print the closing brace.
        write!(f, "\n{:indent$}}}", "", indent = depth * INDENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse_future() {
        // No argument case.
        let expected = r"{
  program_id: credits.aleo,
  function_name: transfer,
  arguments: []
}";
        let (remainder, candidate) =
            Future::<CurrentNetwork>::parse("{ program_id: credits.aleo, function_name: transfer, arguments: [] }")
                .unwrap();
        assert!(remainder.is_empty());
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);

        // Literal arguments.
        let expected = r"{
  program_id: credits.aleo,
  function_name: transfer_public_to_private,
  arguments: [
    aleo1g8qul5a44vk22u9uuvaewdcjw4v6xg8wx0llru39nnjn7eu08yrscxe4e2,
    100000000u64
  ]
}";
        let (remainder, candidate) = Future::<CurrentNetwork>::parse(
            "{ program_id: credits.aleo, function_name: transfer_public_to_private, arguments: [ aleo1g8qul5a44vk22u9uuvaewdcjw4v6xg8wx0llru39nnjn7eu08yrscxe4e2, 100000000u64 ] }",
        ).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
    }

    #[test]
    fn test_parse_display_roundtrip() {
        // Create a future with various argument types.
        let inner = Future::<CurrentNetwork>::new(
            ProgramID::from_str("inner.aleo").unwrap(),
            Identifier::from_str("bar").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("42u64").unwrap())],
        );

        let expected = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap()), Argument::Future(inner)],
        );

        // Convert to string and parse back.
        let string = expected.to_string();
        let candidate = Future::<CurrentNetwork>::from_str(&string).unwrap();

        assert_eq!(expected, candidate);
    }

    #[test]
    fn test_parse_future_with_dynamic_future_argument() {
        // Create an inner future and convert to dynamic.
        let inner = Future::<CurrentNetwork>::new(
            ProgramID::from_str("inner.aleo").unwrap(),
            Identifier::from_str("bar").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("42u64").unwrap())],
        );
        let dynamic_inner = DynamicFuture::from_future(&inner).unwrap();

        // Create a future with a dynamic future argument.
        let expected = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![Argument::DynamicFuture(dynamic_inner)],
        );

        // Convert to string and parse back.
        let string = expected.to_string();
        let candidate = Future::<CurrentNetwork>::from_str(&string).unwrap();

        // Verify structure.
        assert_eq!(expected.program_id(), candidate.program_id());
        assert_eq!(expected.function_name(), candidate.function_name());
        assert_eq!(expected.arguments().len(), candidate.arguments().len());

        // Verify the dynamic future argument matches.
        match (&expected.arguments()[0], &candidate.arguments()[0]) {
            (Argument::DynamicFuture(e), Argument::DynamicFuture(c)) => {
                assert_eq!(e.program_name(), c.program_name());
                assert_eq!(e.program_network(), c.program_network());
                assert_eq!(e.function_name(), c.function_name());
                assert_eq!(e.checksum(), c.checksum());
            }
            _ => panic!("Expected DynamicFuture argument"),
        }
    }

    #[test]
    fn test_deeply_nested_future() {
        // A helper function to iteratively create a deeply nested future.
        fn create_nested_future(depth: usize) -> String {
            // Define the base case.
            let root = r"{
                program_id: foo.aleo,
                function_name: bar,
                arguments: []
            }";
            // Define the prefix and suffix for the nested future.
            let prefix = r"{
                program_id: foo.aleo,
                function_name: bar,
                arguments: ["
                .repeat(depth);
            let suffix = r"]}".repeat(depth);
            // Concatenate the prefix, root, and suffix to create the nested future.
            format!("{prefix}{root}{suffix}")
        }

        // A helper function to test the parsing of a deeply nested future.
        fn run_test(depth: usize, expected_error: bool) {
            // Create the nested future string.
            let nested_future_string = create_nested_future(depth);
            // Parse the nested future.
            let result = Future::<CurrentNetwork>::parse(&nested_future_string);
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
            // Ensure the remainder is empty.
            assert!(
                remainder.is_empty(),
                "Failed to parse deeply nested future. Found invalid character in: \"{remainder}\""
            );
            // Strip the expected string of whitespace.
            let expected = nested_future_string.replace("\n", "").replace(" ", "").replace("\t", "");
            // Strip the candidate string of whitespace.
            let candidate_str = candidate.to_string().replace("\n", "").replace(" ", "").replace("\t", "");
            // Ensure the expected and candidate strings are equal.
            assert_eq!(expected, candidate_str, "Expected: {expected}, Candidate: {candidate_str}");
        }

        // Initialize a set of depths to test.
        let mut depths = (0usize..100).collect_vec();
        depths.extend((100..1000).step_by(100));
        depths.extend((1000..10000).step_by(1000));
        depths.extend((10000..100000).step_by(10000));

        // For each depth, test the parsing of a deeply nested future.
        for depth in depths {
            run_test(depth, depth > CurrentNetwork::MAX_DATA_DEPTH);
        }
    }
}
