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

impl<N: Network> Parser for Mapping<N> {
    /// Parses a string into a mapping.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the 'mapping' keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the mapping name from the string.
        let (string, name) = Identifier::<N>::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the colon ':' keyword from the string.
        let (string, _) = tag(":")(string)?;

        // Parse the key statement from the string.
        let (string, key) = MapKey::parse(string)?;
        // Parse the value statement from the string.
        let (string, value) = MapValue::parse(string)?;

        // Return the mapping.
        Ok((string, Self::new(name, key, value)))
    }
}

impl<N: Network> FromStr for Mapping<N> {
    type Err = Error;

    /// Returns a mapping from a string literal.
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

impl<N: Network> Debug for Mapping<N> {
    /// Prints the mapping as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Mapping<N> {
    /// Prints the mapping as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Write the mapping to a string.
        write!(f, "{} {}:", Self::type_name(), self.name)?;
        write!(f, "\n    {}", self.key)?;
        write!(f, "\n    {}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_mapping_parse() {
        let mapping = Mapping::<CurrentNetwork>::parse(
            r"
mapping foo:
    key as field.public;
    value as field.public;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", mapping.name().to_string());
        assert_eq!("field", mapping.key.plaintext_type().to_string());
        assert_eq!("field", mapping.value.plaintext_type().to_string());
    }

    #[test]
    fn test_mapping_display() {
        let expected = r"mapping foo:
    key as field.public;
    value as field.public;";
        let mapping = Mapping::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(expected, format!("{mapping}"),);
    }
}
