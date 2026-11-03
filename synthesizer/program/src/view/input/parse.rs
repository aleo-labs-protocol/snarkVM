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

impl<N: Network> Parser for Input<N> {
    /// Parses a string into an input statement.
    /// The input statement is of the form `input {register} as {plaintext_type}.public;`.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the input keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the register from the string.
        let (string, register) = map_res(Register::parse, |register| match &register {
            Register::Locator(..) => Ok(register),
            Register::Access(..) => Err(error(format!("Input register {register} cannot be a register member"))),
        })(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "as" from the string.
        let (string, _) = tag("as")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the finalize type from the string.
        let (string, finalize_type) = FinalizeType::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the semicolon from the string.
        let (string, _) = tag(";")(string)?;
        // Return the input statement.
        Ok((string, Self { register, finalize_type }))
    }
}

impl<N: Network> FromStr for Input<N> {
    type Err = Error;

    #[inline]
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<N: Network> Debug for Input<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Input<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {} as {};", Self::type_name(), self.register, self.finalize_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_input_parse() -> Result<()> {
        let input = Input::<CurrentNetwork>::parse("input r0 as field.public;").unwrap().1;
        assert_eq!(input.register(), &Register::<CurrentNetwork>::Locator(0));
        assert_eq!(input.finalize_type(), &FinalizeType::<CurrentNetwork>::from_str("field.public")?);

        let input = Input::<CurrentNetwork>::parse("input r1 as u64.public;").unwrap().1;
        assert_eq!(input.register(), &Register::<CurrentNetwork>::Locator(1));
        assert_eq!(input.finalize_type(), &FinalizeType::<CurrentNetwork>::from_str("u64.public")?);

        let input = Input::<CurrentNetwork>::parse("input r2 as address.public;").unwrap().1;
        assert_eq!(input.register(), &Register::<CurrentNetwork>::Locator(2));
        assert_eq!(input.finalize_type(), &FinalizeType::<CurrentNetwork>::from_str("address.public")?);

        Ok(())
    }

    #[test]
    fn test_input_display() -> Result<()> {
        let input = Input::<CurrentNetwork>::from_str("input r0 as field.public;")?;
        assert_eq!("input r0 as field.public;", input.to_string());

        let input = Input::<CurrentNetwork>::from_str("input r3 as u64.public;")?;
        assert_eq!("input r3 as u64.public;", input.to_string());

        Ok(())
    }

    #[test]
    fn test_input_parse_fails() {
        // Register member is rejected (must be a locator).
        assert!(Input::<CurrentNetwork>::from_str("input r0.x as field.public;").is_err());
        // Missing trailing semicolon.
        assert!(Input::<CurrentNetwork>::from_str("input r0 as field.public").is_err());
        // Missing 'as' keyword.
        assert!(Input::<CurrentNetwork>::from_str("input r0 field.public;").is_err());
        // Missing register.
        assert!(Input::<CurrentNetwork>::from_str("input as field.public;").is_err());
        // Missing 'input' keyword.
        assert!(Input::<CurrentNetwork>::from_str("r0 as field.public;").is_err());
        // Missing finalize type.
        assert!(Input::<CurrentNetwork>::from_str("input r0 as ;").is_err());
    }
}
