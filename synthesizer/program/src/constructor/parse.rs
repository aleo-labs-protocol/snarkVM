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

impl<N: Network> Parser for ConstructorCore<N> {
    /// Parses a string into constructor.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the 'constructor' keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the colon ':' keyword from the string.
        let (string, _) = tag(":")(string)?;

        // Parse the commands from the string.
        let (string, commands) = many1(Command::parse)(string)?;

        map_res(take(0usize), move |_| {
            // Initialize a new constructor.
            let mut constructor = Self { commands: Default::default(), num_writes: 0, positions: Default::default() };
            if let Err(error) = commands.iter().cloned().try_for_each(|command| constructor.add_command(command)) {
                eprintln!("{error}");
                return Err(error);
            }
            Ok::<_, Error>(constructor)
        })(string)
    }
}

impl<N: Network> FromStr for ConstructorCore<N> {
    type Err = Error;

    /// Returns a constructor from a string literal.
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

impl<N: Network> Debug for ConstructorCore<N> {
    /// Prints the constructor as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for ConstructorCore<N> {
    /// Prints the constructor as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Write the constructor to a string.
        write!(f, "{}:", Self::type_name())?;
        self.commands.iter().try_for_each(|command| write!(f, "\n    {command}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Constructor;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_constructor_parse() {
        let constructor = Constructor::<CurrentNetwork>::parse(
            r"
constructor:
    add r0 r1 into r2;",
        )
        .unwrap()
        .1;
        assert_eq!(1, constructor.commands().len());

        // Constructor with 0 inputs.
        let constructor = Constructor::<CurrentNetwork>::parse(
            r"
constructor:
    add 1u32 2u32 into r0;",
        )
        .unwrap()
        .1;
        assert_eq!(1, constructor.commands().len());
    }

    #[test]
    fn test_constructor_parse_cast() {
        let constructor = Constructor::<CurrentNetwork>::parse(
            r"
constructor:
    cast 1u8 2u8 into r1 as token;",
        )
        .unwrap()
        .1;
        assert_eq!(1, constructor.commands().len());
    }

    #[test]
    fn test_constructor_display() {
        let expected = r"constructor:
    add r0 r1 into r2;";
        let constructor = Constructor::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(expected, format!("{constructor}"),);
    }

    #[test]
    fn test_empty_constructor() {
        // Test that parsing an empty constructor fails.
        assert!(Constructor::<CurrentNetwork>::parse("constructor:").is_err());
        // Test that attempting to serialize an empty constructor fails.
        let constructor = Constructor::<CurrentNetwork> {
            commands: Default::default(),
            num_writes: 0,
            positions: Default::default(),
        };
        assert!(constructor.write_le(Vec::new()).is_err());
    }
}
