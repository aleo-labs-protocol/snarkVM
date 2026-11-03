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

impl Parser for LiteralType {
    /// Parses a string into a literal type.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the type from the string.
        alt((
            map(tag(Self::Address.type_name()), |_| Self::Address),
            map(tag(Self::Boolean.type_name()), |_| Self::Boolean),
            map(tag(Self::Field.type_name()), |_| Self::Field),
            map(tag(Self::Group.type_name()), |_| Self::Group),
            map(tag(Self::I8.type_name()), |_| Self::I8),
            map(tag(Self::I16.type_name()), |_| Self::I16),
            map(tag(Self::I32.type_name()), |_| Self::I32),
            map(tag(Self::I64.type_name()), |_| Self::I64),
            map(tag(Self::I128.type_name()), |_| Self::I128),
            map(tag(Self::U8.type_name()), |_| Self::U8),
            map(tag(Self::U16.type_name()), |_| Self::U16),
            map(tag(Self::U32.type_name()), |_| Self::U32),
            map(tag(Self::U64.type_name()), |_| Self::U64),
            map(tag(Self::U128.type_name()), |_| Self::U128),
            map(tag(Self::Scalar.type_name()), |_| Self::Scalar),
            map(tag(Self::Signature.type_name()), |_| Self::Signature),
            map(tag(Self::String.type_name()), |_| Self::String),
            map(tag(Self::Identifier.type_name()), |_| Self::Identifier),
        ))(string)
    }
}

impl FromStr for LiteralType {
    type Err = Error;

    /// Returns a literal type from a string literal.
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

impl Debug for LiteralType {
    /// Prints the literal type as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.type_name())
    }
}

impl Display for LiteralType {
    /// Prints the literal type as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.type_name())
    }
}
