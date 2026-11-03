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

impl<N: Network> Parser for Locator<N> {
    /// Parses a string into a locator of the form `{program_id}/{resource}`.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the program ID from the string.
        let (string, id) = ProgramID::parse(string)?;
        // Parse the "/" and resource from the string.
        let (string, (_, resource)) = pair(tag("/"), Identifier::parse)(string)?;
        // Return the locator.
        Ok((string, Self { id, resource }))
    }
}

impl<N: Network> FromStr for Locator<N> {
    type Err = Error;

    /// Parses a string into a locator.
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

impl<N: Network> Debug for Locator<N> {
    /// Prints the locator as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Locator<N> {
    /// Prints the locator as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{id}/{resource}", id = self.id, resource = self.resource)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_import_parse() -> Result<()> {
        let locator = Locator::<CurrentNetwork>::parse("foo.aleo/compute").unwrap().1;
        assert_eq!(locator.name(), &Identifier::<CurrentNetwork>::from_str("foo")?);
        assert_eq!(locator.network(), &Identifier::<CurrentNetwork>::from_str("aleo")?);
        assert_eq!(locator.resource(), &Identifier::<CurrentNetwork>::from_str("compute")?);

        assert!(Locator::<CurrentNetwork>::parse("foo.aleo").is_err());
        assert!(Locator::<CurrentNetwork>::parse("foo/compute").is_err());

        Ok(())
    }

    #[test]
    fn test_import_display() -> Result<()> {
        let id = Locator::<CurrentNetwork>::from_str("foo.aleo/compute")?;
        assert_eq!("foo.aleo/compute", id.to_string());

        assert!(Locator::<CurrentNetwork>::parse("foo.aleo").is_err());
        assert!(Locator::<CurrentNetwork>::parse("foo/compute").is_err());

        Ok(())
    }
}
