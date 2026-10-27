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
use crate::Command;

impl<N: Network> Parser for FinalizeCore<N> {
    /// Parses a string into finalize.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the 'finalize' keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the associated function name from the string.
        let (string, name) = Identifier::<N>::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the colon ':' keyword from the string.
        let (string, _) = tag(":")(string)?;

        // Parse the inputs from the string.
        let (string, inputs) = many0(Input::parse)(string)?;
        // Parse the commands from the string.
        let (string, commands) = many1(Command::<N>::parse)(string)?;

        map_res(take(0usize), move |_| {
            // Initialize a new finalize.
            let mut finalize = Self::new(name);
            if let Err(error) = inputs.iter().cloned().try_for_each(|input| finalize.add_input(input)) {
                eprintln!("{error}");
                return Err(error);
            }
            if let Err(error) = commands.iter().cloned().try_for_each(|command| finalize.add_command(command)) {
                eprintln!("{error}");
                return Err(error);
            }
            Ok::<_, Error>(finalize)
        })(string)
    }
}

impl<N: Network> FromStr for FinalizeCore<N> {
    type Err = Error;

    /// Returns a finalize from a string literal.
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

impl<N: Network> Debug for FinalizeCore<N> {
    /// Prints the finalize as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for FinalizeCore<N> {
    /// Prints the finalize as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Write the finalize to a string.
        write!(f, "{} {}:", Self::type_name(), self.name)?;
        self.inputs.iter().try_for_each(|input| write!(f, "\n    {input}"))?;
        self.commands.iter().try_for_each(|command| write!(f, "\n    {command}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Finalize;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_finalize_parse() {
        let finalize = Finalize::<CurrentNetwork>::parse(
            r"
finalize foo:
    input r0 as field.public;
    input r1 as field.public;
    add r0 r1 into r2;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", finalize.name().to_string());
        assert_eq!(2, finalize.inputs().len());
        assert_eq!(1, finalize.commands().len());

        // Finalize with 0 inputs.
        let finalize = Finalize::<CurrentNetwork>::parse(
            r"
finalize foo:
    add 1u32 2u32 into r0;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", finalize.name().to_string());
        assert_eq!(0, finalize.inputs().len());
        assert_eq!(1, finalize.commands().len());
    }

    #[test]
    fn test_finalize_parse_cast() {
        let finalize = Finalize::<CurrentNetwork>::parse(
            r"
finalize foo:
    input r0 as token.public;
    cast r0.owner r0.token_amount into r1 as token;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", finalize.name().to_string());
        assert_eq!(1, finalize.inputs().len());
        assert_eq!(1, finalize.commands().len());
    }

    #[test]
    fn test_finalize_display() {
        let expected = r"finalize foo:
    input r0 as field.public;
    input r1 as field.public;
    add r0 r1 into r2;";
        let finalize = Finalize::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(expected, format!("{finalize}"),);
    }
}
