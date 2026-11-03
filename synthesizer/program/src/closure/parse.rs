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

impl<N: Network> Parser for ClosureCore<N> {
    /// Parses a string into a closure.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the 'closure' keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the closure name from the string.
        let (string, name) = Identifier::<N>::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the colon ':' keyword from the string.
        let (string, _) = tag(":")(string)?;

        // Parse the inputs from the string.
        let (string, inputs) = many1(Input::parse)(string)?;
        // Parse the instructions from the string.
        let (string, instructions) = many1(Instruction::parse)(string)?;
        // Parse the outputs from the string.
        let (string, outputs) = many0(Output::parse)(string)?;

        map_res(take(0usize), move |_| {
            // Initialize a new closure.
            let mut closure = Self::new(name);
            inputs.iter().cloned().try_for_each(|input| closure.add_input(input))?;
            instructions.iter().cloned().try_for_each(|instruction| closure.add_instruction(instruction))?;
            outputs.iter().cloned().try_for_each(|output| closure.add_output(output))?;
            Ok::<_, Error>(closure)
        })(string)
    }
}

impl<N: Network> FromStr for ClosureCore<N> {
    type Err = Error;

    /// Returns a closure from a string literal.
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

impl<N: Network> Debug for ClosureCore<N> {
    /// Prints the closure as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for ClosureCore<N> {
    /// Prints the closure as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Write the closure to a string.
        write!(f, "{} {}:", Self::type_name(), self.name)?;
        self.inputs.iter().try_for_each(|input| write!(f, "\n    {input}"))?;
        self.instructions.iter().try_for_each(|instruction| write!(f, "\n    {instruction}"))?;
        self.outputs.iter().try_for_each(|output| write!(f, "\n    {output}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Closure;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_closure_parse() {
        let closure = Closure::<CurrentNetwork>::parse(
            r"
closure foo:
    input r0 as field;
    input r1 as field;
    add r0 r1 into r2;
    output r2 as field;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", closure.name().to_string());
        assert_eq!(2, closure.inputs().len());
        assert_eq!(1, closure.instructions().len());
        assert_eq!(1, closure.outputs().len());
    }

    #[test]
    fn test_closure_parse_cast() {
        let closure = Closure::<CurrentNetwork>::parse(
            r"
closure foo:
    input r0 as token.record;
    cast r0.owner r0.token_amount into r1 as data;
    output r1 as data;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", closure.name().to_string());
        assert_eq!(1, closure.inputs().len());
        assert_eq!(1, closure.instructions().len());
        assert_eq!(1, closure.outputs().len());
    }

    #[test]
    fn test_closure_display() {
        let expected = r"closure foo:
    input r0 as field;
    input r1 as field;
    add r0 r1 into r2;
    output r2 as field;";
        let closure = Closure::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(expected, format!("{closure}"),);
    }

    #[test]
    fn test_closure_parse_output_function() {
        let result = Closure::<CurrentNetwork>::parse(
            r"
closure foo:
    input r0 as token.record;
    cast r0.owner r0.token_amount into r1 as token.record;
    output r1 as token.record;",
        );

        assert!(result.is_err());
    }
}
