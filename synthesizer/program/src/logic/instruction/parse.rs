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

impl<N: Network> Parser for Instruction<N> {
    /// Parses a string into an instruction.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Create an alt parser that matches the instruction.
        ///
        /// `nom` documentation notes that alt supports a maximum of 21 parsers.
        /// The documentation suggests to nest alt to support more parsers, as we do here.
        /// Note that order of the individual parsers matters.
        macro_rules! alt_parser {
            ($v0:expr) => {{ alt(($v0,)) }};
            ($v0:expr, $v1:expr) => {{ alt(($v0, $v1,)) }};
            ($v0:expr, $v1:expr, $v2:expr) => {{ alt(($v0, $v1, $v2,)) }};
            ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {{ alt(($v0, $v1, $v2, $v3,)) }};
            ($v0:expr, $v1:expr, $v2:expr, $v3:expr, $v4:expr) => {{ alt(($v0, $v1, $v2, $v3, $v4,)) }};
            ($v0:expr, $v1:expr, $v2:expr, $v3:expr, $v4:expr, $v5:expr) => {{ alt(($v0, $v1, $v2, $v3, $v4, $v5,)) }};
            ($v0:expr, $v1:expr, $v2:expr, $v3:expr, $v4:expr, $v5:expr, $v6:expr) => {{ alt(($v0, $v1, $v2, $v3, $v4, $v5, $v6,)) }};
            ($v0:expr, $v1:expr, $v2:expr, $v3:expr, $v4:expr, $v5:expr, $v6:expr, $v7:expr) => {{ alt(($v0, $v1, $v2, $v3, $v4, $v5, $v6, $v7,)) }};
            ($v0:expr, $v1:expr, $v2:expr, $v3:expr, $v4:expr, $v5:expr, $v6:expr, $v7:expr, $v8:expr) => {{ alt(($v0, $v1, $v2, $v3, $v4, $v5, $v6, $v7, $v8,)) }};
            ($v0:expr, $v1:expr, $v2:expr, $v3:expr, $v4:expr, $v5:expr, $v6:expr, $v7:expr, $v8:expr, $v9:expr) => {{ alt(($v0, $v1, $v2, $v3, $v4, $v5, $v6, $v7, $v8, $v9,)) }};
            ($v0:expr, $v1:expr, $v2:expr, $v3:expr, $v4:expr, $v5:expr, $v6:expr, $v7:expr, $v8:expr, $v9:expr, $( $variants:expr ),*) => {{ alt((
                alt_parser!($( $variants ),*), $v0, $v1, $v2, $v3, $v4, $v5, $v6, $v7, $v8, $v9,
            )) }};
        }

        /// Creates a parser for the given instructions.
        ///
        /// ## Example
        /// ```ignore
        /// instruction_parsers!(self, |_instruction| {}, { Add, Sub, Mul, Div })
        /// ```
        macro_rules! instruction_parsers {
            ($object:expr, |_instruction| $_operation:block, { $( $variant:ident, )+ }) => {{
                alt_parser!( $( map($variant::parse, Into::into) ),+ )
            }};
        }

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the instruction from the string.
        let (string, instruction) = crate::instruction!(instruction_parsers!(self, _instruction))(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the semicolon from the string.
        let (string, _) = tag(";")(string)?;

        Ok((string, instruction))
    }
}

impl<N: Network> FromStr for Instruction<N> {
    type Err = Error;

    /// Parses a string into an instruction.
    #[inline]
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

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() -> Result<()> {
        let instruction = "add r0 r1 into r2;";
        let (remainder, candidate) = Instruction::<CurrentNetwork>::parse(instruction)?;
        assert_eq!("", remainder);
        assert_eq!(instruction, candidate.to_string());
        Ok(())
    }
}
