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

impl<E: Environment, I: IntegerType> Parser for Integer<E, I> {
    /// Parses a string into a integer circuit.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the negative sign '-' from the string.
        let (string, negation) = map(opt(tag("-")), |neg: Option<&str>| neg.unwrap_or_default().to_string())(string)?;
        // Parse the digits from the string.
        let (string, primitive) = recognize(many1(terminated(one_of("0123456789"), many0(char('_')))))(string)?;
        // Combine the sign and primitive.
        let primitive = negation + primitive;
        // Parse the value from the string.
        let (string, value) = map_res(tag(Self::type_name()), |_| primitive.replace('_', "").parse())(string)?;

        Ok((string, Integer::new(value)))
    }
}

impl<E: Environment, I: IntegerType> FromStr for Integer<E, I> {
    type Err = Error;

    /// Parses a string into an integer.
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

impl<E: Environment, I: IntegerType> Debug for Integer<E, I> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<E: Environment, I: IntegerType> Display for Integer<E, I> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}{}", self.integer, Self::type_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 10_000;

    #[test]
    fn test_parse() -> Result<()> {
        let rng = &mut TestRng::default();

        // Ensure empty value fails.
        assert!(Integer::<CurrentEnvironment, i8>::parse(Integer::<CurrentEnvironment, i8>::type_name()).is_err());
        assert!(Integer::<CurrentEnvironment, i8>::parse("").is_err());

        for _ in 0..ITERATIONS {
            // Sample a random value.
            let integer: i8 = Uniform::rand(rng);

            let expected = format!("{}{}", integer, Integer::<CurrentEnvironment, i8>::type_name());
            let (remainder, candidate) = Integer::<CurrentEnvironment, i8>::parse(&expected).unwrap();
            assert_eq!(format!("{expected}"), candidate.to_string());
            assert_eq!("", remainder);
        }
        Ok(())
    }

    #[test]
    fn test_display() {
        /// Attempts to construct a integer from the given element,
        /// format it in display mode, and recover a integer from it.
        fn check_display<E: Environment, I: IntegerType>(rng: &mut TestRng) {
            for _ in 0..ITERATIONS {
                let element = Uniform::rand(rng);

                let candidate = Integer::<E, I>::new(element);
                assert_eq!(format!("{element}{}", Integer::<E, I>::type_name()), format!("{candidate}"));

                let candidate_recovered = Integer::<E, I>::from_str(&format!("{candidate}")).unwrap();
                assert_eq!(candidate, candidate_recovered);
            }
        }

        let mut rng = TestRng::default();

        check_display::<CurrentEnvironment, u8>(&mut rng);
        check_display::<CurrentEnvironment, u16>(&mut rng);
        check_display::<CurrentEnvironment, u32>(&mut rng);
        check_display::<CurrentEnvironment, u64>(&mut rng);
        check_display::<CurrentEnvironment, u128>(&mut rng);

        check_display::<CurrentEnvironment, i8>(&mut rng);
        check_display::<CurrentEnvironment, i16>(&mut rng);
        check_display::<CurrentEnvironment, i32>(&mut rng);
        check_display::<CurrentEnvironment, i64>(&mut rng);
        check_display::<CurrentEnvironment, i128>(&mut rng);
    }

    #[test]
    fn test_display_zero() {
        let zero = i8::zero();

        let candidate = Integer::<CurrentEnvironment, i8>::new(zero);
        assert_eq!("0i8", &format!("{candidate}"));
    }

    #[test]
    fn test_display_one() {
        let one = i8::one();

        let candidate = Integer::<CurrentEnvironment, i8>::new(one);
        assert_eq!("1i8", &format!("{candidate}"));
    }

    #[test]
    fn test_display_two() {
        let one = i8::one();
        let two = one + one;

        let candidate = Integer::<CurrentEnvironment, i8>::new(two);
        assert_eq!("2i8", &format!("{candidate}"));
    }
}
