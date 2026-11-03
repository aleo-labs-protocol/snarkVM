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

impl<E: Environment> Parser for Group<E> {
    /// Parses a string into a group circuit.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the optional negative sign '-' from the string.
        let (string, negation) = map(opt(tag("-")), |neg: Option<&str>| neg.is_some())(string)?;
        // Parse the digits from the string.
        let (string, primitive) = recognize(many1(terminated(one_of("0123456789"), many0(char('_')))))(string)?;
        // Parse the group from the string.
        let (string, group): (&str, Self) = map_res(tag(Self::type_name()), |_| {
            let x_coordinate = primitive.replace('_', "").parse()?;
            // Recover and negate the group element if the negative sign was present.
            match negation {
                true => Ok(-Group::from_x_coordinate(Field::new(x_coordinate))?),
                false => Group::from_x_coordinate(Field::new(x_coordinate)),
            }
        })(string)?;

        Ok((string, group))
    }
}

impl<E: Environment> FromStr for Group<E> {
    type Err = Error;

    /// Parses a string into a group.
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

impl<E: Environment> Debug for Group<E> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<E: Environment> Display for Group<E> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}{}", self.group.to_affine().to_x_coordinate(), Self::type_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 1_000;

    #[test]
    fn test_parse() -> Result<()> {
        let rng = &mut TestRng::default();

        // Ensure empty value fails.
        assert!(Group::<CurrentEnvironment>::parse(Group::<CurrentEnvironment>::type_name()).is_err());
        assert!(Group::<CurrentEnvironment>::parse("").is_err());

        for _ in 0..ITERATIONS {
            // Sample a random value.
            let group: <CurrentEnvironment as Environment>::Affine = Uniform::rand(rng);

            let expected = format!("{}{}", group.to_x_coordinate(), Group::<CurrentEnvironment>::type_name());
            let (remainder, candidate) = Group::<CurrentEnvironment>::parse(&expected).unwrap();
            assert_eq!(format!("{expected}"), candidate.to_string());
            assert_eq!("", remainder);
        }
        Ok(())
    }

    #[test]
    fn test_display() {
        /// Attempts to construct a group from the given element,
        /// format it in display mode, and recover a group from it.
        fn check_display<E: Environment>(element: E::Affine) {
            let candidate = Group::<E>::new(element);
            assert_eq!(format!("{}{}", element.to_x_coordinate(), Group::<E>::type_name()), format!("{candidate}"));

            let candidate_recovered = Group::<E>::from_str(&format!("{candidate}")).unwrap();
            assert_eq!(candidate, candidate_recovered);
        }

        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let element = Uniform::rand(&mut rng);

            check_display::<CurrentEnvironment>(element);
        }
    }

    #[test]
    fn test_display_zero() {
        let zero = <CurrentEnvironment as Environment>::Affine::zero();

        let candidate = Group::<CurrentEnvironment>::new(zero);
        assert_eq!("0group", &format!("{candidate}"));
    }
}
