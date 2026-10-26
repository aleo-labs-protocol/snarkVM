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

impl<N: Network> Parser for Literal<N> {
    /// Parses a string into a literal.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        alt((
            map(Address::<N>::parse, |literal| Self::Address(literal)),
            map(Boolean::<N>::parse, |literal| Self::Boolean(literal)),
            map(Field::<N>::parse, |literal| Self::Field(literal)),
            map(Group::<N>::parse, |literal| Self::Group(literal)),
            map(I8::<N>::parse, |literal| Self::I8(literal)),
            map(I16::<N>::parse, |literal| Self::I16(literal)),
            map(I32::<N>::parse, |literal| Self::I32(literal)),
            map(I64::<N>::parse, |literal| Self::I64(literal)),
            map(I128::<N>::parse, |literal| Self::I128(literal)),
            map(U8::<N>::parse, |literal| Self::U8(literal)),
            map(U16::<N>::parse, |literal| Self::U16(literal)),
            map(U32::<N>::parse, |literal| Self::U32(literal)),
            map(U64::<N>::parse, |literal| Self::U64(literal)),
            map(U128::<N>::parse, |literal| Self::U128(literal)),
            map(Scalar::<N>::parse, |literal| Self::Scalar(literal)),
            map(Signature::<N>::parse, |literal| Self::Signature(Box::new(literal))),
            map(IdentifierLiteral::<N>::parse, |literal| Self::Identifier(Box::new(literal))),
            map(StringType::<N>::parse, |literal| Self::String(literal)),
            // This allows users to implicitly declare program IDs as literals.
            map_res(ProgramID::<N>::parse, |program_id| Ok::<Self, Error>(Self::Address(program_id.to_address()?))),
        ))(string)
    }
}

impl<N: Network> FromStr for Literal<N> {
    type Err = Error;

    /// Parses a string into a literal.
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

impl<N: Network> Debug for Literal<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Literal<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Address(literal) => Display::fmt(literal, f),
            Self::Boolean(literal) => Display::fmt(literal, f),
            Self::Field(literal) => Display::fmt(literal, f),
            Self::Group(literal) => Display::fmt(literal, f),
            Self::I8(literal) => Display::fmt(literal, f),
            Self::I16(literal) => Display::fmt(literal, f),
            Self::I32(literal) => Display::fmt(literal, f),
            Self::I64(literal) => Display::fmt(literal, f),
            Self::I128(literal) => Display::fmt(literal, f),
            Self::U8(literal) => Display::fmt(literal, f),
            Self::U16(literal) => Display::fmt(literal, f),
            Self::U32(literal) => Display::fmt(literal, f),
            Self::U64(literal) => Display::fmt(literal, f),
            Self::U128(literal) => Display::fmt(literal, f),
            Self::Scalar(literal) => Display::fmt(literal, f),
            Self::Signature(literal) => Display::fmt(literal, f),
            Self::String(literal) => Display::fmt(literal, f),
            Self::Identifier(literal) => Display::fmt(literal, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse_program_id() -> Result<()> {
        let (remainder, candidate) = Literal::<CurrentNetwork>::parse("credits.aleo")?;
        assert!(matches!(candidate, Literal::Address(_)));
        assert_eq!(candidate.to_string(), "aleo1lqmly7ez2k48ajf5hs92ulphaqr05qm4n8qwzj8v0yprmasgpqgsez59gg");
        assert_eq!("", remainder);

        let result = Literal::<CurrentNetwork>::parse("credits.ale");
        assert!(result.is_err());

        let result = Literal::<CurrentNetwork>::parse("credits.aleo1");
        assert!(result.is_err());

        Ok(())
    }
}
