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

impl<E: Environment> Parser for Boolean<E> {
    /// Parses a string into a boolean.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the boolean from the string.
        let (string, value) = alt((map(tag("true"), |_| true), map(tag("false"), |_| false)))(string)?;

        Ok((string, Boolean::new(value)))
    }
}

impl<E: Environment> FromStr for Boolean<E> {
    type Err = Error;

    /// Parses a string into a boolean.
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

impl<E: Environment> Debug for Boolean<E> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<E: Environment> Display for Boolean<E> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.boolean)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    #[test]
    fn test_parse() -> Result<()> {
        // Ensure type and empty value fails.
        assert!(Boolean::<CurrentEnvironment>::parse(Boolean::<CurrentEnvironment>::type_name()).is_err());
        assert!(Boolean::<CurrentEnvironment>::parse("").is_err());

        for boolean in &[true, false] {
            let expected = format!("{boolean}");
            let (remainder, candidate) = Boolean::<CurrentEnvironment>::parse(&expected).unwrap();
            assert_eq!(format!("{expected}"), candidate.to_string());
            assert_eq!("", remainder);
        }
        Ok(())
    }

    #[test]
    fn test_display() {
        /// Attempts to construct a boolean from the given element,
        /// format it in display mode, and recover a boolean from it.
        fn check_display<E: Environment>(element: bool) {
            let candidate = Boolean::<E>::new(element);
            assert_eq!(format!("{element}"), format!("{candidate}"));

            let candidate_recovered = Boolean::<E>::from_str(&format!("{candidate}")).unwrap();
            assert_eq!(candidate, candidate_recovered);
        }

        check_display::<CurrentEnvironment>(false);
        check_display::<CurrentEnvironment>(true);
    }

    #[test]
    fn test_display_false() {
        // Constant
        let candidate = Boolean::<CurrentEnvironment>::new(false);
        assert_eq!("false", &format!("{candidate}"));
    }

    #[test]
    fn test_display_true() {
        // Constant
        let candidate = Boolean::<CurrentEnvironment>::new(true);
        assert_eq!("true", &format!("{candidate}"));
    }
}
