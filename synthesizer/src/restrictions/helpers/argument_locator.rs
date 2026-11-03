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

use console::network::prelude::*;

/// A locator for a function argument of the form `{is_input}/{index}`.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct ArgumentLocator {
    /// The `is_input` flag is `true` if the argument is an input, otherwise it is an output.
    is_input: bool,
    /// The (zero-based) index of the argument.
    index: u16,
}

impl ArgumentLocator {
    /// Initializes a new argument locator.
    pub const fn new(is_input: bool, index: u16) -> Self {
        Self { is_input, index }
    }

    /// Returns the `is_input` flag.
    pub const fn is_input(&self) -> bool {
        self.is_input
    }

    /// Returns the index.
    pub const fn index(&self) -> u16 {
        self.index
    }
}

impl Parser for ArgumentLocator {
    /// Parses a string into an argument locator of the form `{is_input}/{index}`.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the `is_input` from the string.
        let (string, is_input) = alt((map(tag("true"), |_| true), map(tag("false"), |_| false)))(string)?;
        // Parse the `/` from the string.
        let (string, _) = tag("/")(string)?;
        // Parse the `index` from the string.
        let (string, index) =
            map_res(recognize(many1(one_of("0123456789"))), |string: &str| string.parse::<u16>())(string)?;

        // Return the argument locator.
        Ok((string, Self { is_input, index }))
    }
}

impl FromStr for ArgumentLocator {
    type Err = Error;

    /// Parses a string into an argument locator.
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

impl Debug for ArgumentLocator {
    /// Prints the argument locator as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for ArgumentLocator {
    /// Prints the argument locator as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{is_input}/{index}", is_input = self.is_input, index = self.index)
    }
}

impl FromBytes for ArgumentLocator {
    /// Reads the argument locator from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let is_input = FromBytes::read_le(&mut reader)?;
        let index = FromBytes::read_le(&mut reader)?;
        Ok(Self { is_input, index })
    }
}

impl ToBytes for ArgumentLocator {
    /// Writes the argument locator to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.is_input.write_le(&mut writer)?;
        self.index.write_le(&mut writer)
    }
}

impl Serialize for ArgumentLocator {
    /// Serializes the locator into string or bytes.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => serializer.collect_str(self),
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ArgumentLocator {
    /// Deserializes the locator from a string or bytes.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => FromStr::from_str(&String::deserialize(deserializer)?).map_err(de::Error::custom),
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "argument locator"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITERATIONS: usize = 10;

    pub(crate) fn sample_argument_locator<R: Rng + CryptoRng>(rng: &mut R) -> ArgumentLocator {
        ArgumentLocator::new(rng.random(), rng.random_range(0..16))
    }

    fn check_serde_json<
        T: Serialize + for<'a> Deserialize<'a> + Debug + Display + PartialEq + Eq + FromStr + ToBytes + FromBytes,
    >(
        expected: T,
    ) {
        // Serialize
        let expected_string = &expected.to_string();
        let candidate_string = serde_json::to_string(&expected).unwrap();
        assert_eq!(expected_string, serde_json::Value::from_str(&candidate_string).unwrap().as_str().unwrap());

        // Deserialize
        assert_eq!(expected, T::from_str(expected_string).unwrap_or_else(|_| panic!("FromStr: {expected_string}")));
        assert_eq!(expected, serde_json::from_str(&candidate_string).unwrap());
    }

    fn check_bincode<
        T: Serialize + for<'a> Deserialize<'a> + Debug + Display + PartialEq + Eq + FromStr + ToBytes + FromBytes,
    >(
        expected: T,
    ) {
        // Serialize
        let expected_bytes = expected.to_bytes_le().unwrap();
        let expected_bytes_with_size_encoding = bincode::serialize(&expected).unwrap();
        assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

        // Deserialize
        assert_eq!(expected, T::read_le(&expected_bytes[..]).unwrap());
        assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding[..]).unwrap());
    }

    #[test]
    fn test_serde_json() {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            let expected = sample_argument_locator(rng);
            check_serde_json(expected);
        }
    }

    #[test]
    fn test_bincode() {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            let expected = sample_argument_locator(rng);
            check_bincode(expected);
        }
    }

    #[test]
    fn test_import_parse() {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            let expected = sample_argument_locator(rng);

            // Test the parser.
            let argument_locator = ArgumentLocator::parse(&expected.to_string()).unwrap().1;
            assert_eq!(expected.is_input(), argument_locator.is_input());
            assert_eq!(expected.index(), argument_locator.index());

            // Test the from_str.
            let argument_locator = ArgumentLocator::from_str(&expected.to_string()).unwrap();
            assert_eq!(expected.is_input(), argument_locator.is_input());
            assert_eq!(expected.index(), argument_locator.index());
        }
    }
}
