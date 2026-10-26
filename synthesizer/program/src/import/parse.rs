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

impl<N: Network> Parser for Import<N> {
    /// Parses a string into an import statement of the form `import {name}.{network};`.
    /// If no `network`-level domain is specified, the default network is used.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the import keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the program ID from the string.
        let (string, id) = ProgramID::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the semicolon from the string.
        let (string, _) = tag(";")(string)?;
        // Return the import statement.
        Ok((string, Self { program_id: id }))
    }
}

impl<N: Network> FromStr for Import<N> {
    type Err = Error;

    /// Parses a string into an import statement.
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

impl<N: Network> Debug for Import<N> {
    /// Prints the import as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Import<N> {
    /// Prints the import statement as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{type_} {id};", type_ = Self::type_name(), id = self.program_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_import_parse() -> Result<()> {
        let import = Import::<CurrentNetwork>::parse("import bar.aleo;").unwrap().1;
        assert_eq!(import.name(), &Identifier::<CurrentNetwork>::from_str("bar")?);
        assert_eq!(import.network(), &Identifier::<CurrentNetwork>::from_str("aleo")?);

        let import = Import::<CurrentNetwork>::parse("import foo.aleo;").unwrap().1;
        assert_eq!(import.name(), &Identifier::<CurrentNetwork>::from_str("foo")?);
        assert_eq!(import.network(), &Identifier::<CurrentNetwork>::from_str("aleo")?);

        Ok(())
    }

    #[test]
    fn test_import_display() -> Result<()> {
        let import = Import::<CurrentNetwork>::from_str("import bar.aleo;")?;
        assert_eq!("import bar.aleo;", import.to_string());

        let import = Import::<CurrentNetwork>::from_str("import foo.aleo;")?;
        assert_eq!("import foo.aleo;", import.to_string());

        Ok(())
    }
}
