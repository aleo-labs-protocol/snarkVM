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
use crate::{Identifier, LiteralType, Locator};

impl<N: Network> Parser for ArrayType<N> {
    /// Parses a string into a literal type.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // A helper function to parse the innermost element type.
        fn parse_inner_element_type<N: Network>(string: &str) -> ParserResult<'_, PlaintextType<N>> {
            // Order matters - we shouldn't try to parse Identifier before Locator.
            alt((
                map(Locator::parse, PlaintextType::from),
                map(LiteralType::parse, PlaintextType::from),
                map(Identifier::parse, PlaintextType::from),
            ))(string)
        }

        // A helper function to parse the length of each dimension.
        fn parse_length<N: Network>(string: &str) -> ParserResult<'_, U32<N>> {
            // Parse the whitespaces from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the semicolon from the string.
            let (string, _) = tag(";")(string)?;
            // Parse the whitespaces from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the length.
            let (string, length) = U32::parse(string)?;
            // Parse the whitespaces from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the closing bracket.
            let (string, _) = tag("]")(string)?;
            // Return the length.
            Ok((string, length))
        }

        // Parse the opening brackets and validate the number of dimensions.
        let (string, dimensions) = map_res(many0_count(pair(tag("["), Sanitizer::parse_whitespaces)), |dimensions| {
            if dimensions.is_zero() {
                Err("An array must have at least one dimension.".to_string())
            } else if dimensions > N::MAX_DATA_DEPTH {
                Err(format!("Array type exceeds the maximum depth of {}.", N::MAX_DATA_DEPTH))
            } else {
                Ok(dimensions)
            }
        })(string)?;

        // Parse the whitespaces from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the innermost element type and the dimensions and return the array type.
        map_res(pair(parse_inner_element_type, count(parse_length, dimensions)), |(plaintext_type, mut dimensions)| {
            // Reverse the dimensions, since they were parsed from innermost to outermost.
            dimensions.reverse();
            ArrayType::new(plaintext_type, dimensions)
        })(string)
    }
}

impl<N: Network> FromStr for ArrayType<N> {
    type Err = Error;

    /// Returns an array type from a string literal.
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

impl<N: Network> Debug for ArrayType<N> {
    /// Prints the array type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for ArrayType<N> {
    /// Prints the array type as a string.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "[{}; {}]", self.next_element_type(), self.length())
    }
}
