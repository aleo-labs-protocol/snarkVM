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

static STATE_PATH_PREFIX: &str = "path";

impl<N: Network> Parser for StatePath<N> {
    /// Parses a string into the state path.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Prepare a parser for the Aleo state path.
        let parse_state_path = recognize(pair(
            pair(tag(STATE_PATH_PREFIX), tag("1")),
            many1(terminated(one_of("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), many0(char('_')))),
        ));

        // Parse the state path from the string.
        map_res(parse_state_path, |state_path: &str| -> Result<_, Error> {
            Self::from_str(&state_path.replace('_', ""))
        })(string)
    }
}

impl<N: Network> FromStr for StatePath<N> {
    type Err = Error;

    /// Reads in the state path string.
    fn from_str(state_path: &str) -> Result<Self, Self::Err> {
        // Decode the state path string from bech32m.
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<LongBech32m>(state_path)?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        if hrp.as_str() != STATE_PATH_PREFIX {
            bail!("Failed to decode state path: '{hrp}' is an invalid prefix")
        } else if data.is_empty() {
            bail!("Failed to decode state path: data field is empty")
        }
        // Decode the state path data into the state path.
        Ok(Self::read_le(&data[..])?)
    }
}

impl<N: Network> Debug for StatePath<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for StatePath<N> {
    /// Writes the state path as a bech32m string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Convert the state path to bytes.
        let bytes = self.to_bytes_le().map_err(|_| fmt::Error)?;
        // Encode the bytes into bech32m.
        let string = bech32::encode::<LongBech32m>(bech32::Hrp::parse_unchecked(STATE_PATH_PREFIX), &bytes)
            .map_err(|_| fmt::Error)?;
        // Output the string.
        Display::fmt(&string, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: usize = 100;

    #[test]
    fn test_parse() {
        let mut rng = TestRng::default();

        // Ensure type and empty value fails.
        assert!(StatePath::<CurrentNetwork>::parse(&format!("{STATE_PATH_PREFIX}1")).is_err());
        assert!(StatePath::<CurrentNetwork>::parse("").is_err());

        for _ in 0..ITERATIONS {
            // Sample the state path.
            let expected =
                crate::state_path::test_helpers::sample_global_state_path::<CurrentNetwork>(None, &mut rng).unwrap();

            let expected = format!("{expected}");
            let (remainder, candidate) = StatePath::<CurrentNetwork>::parse(&expected).unwrap();
            assert_eq!(format!("{expected}"), candidate.to_string());
            assert_eq!(STATE_PATH_PREFIX, candidate.to_string().split('1').next().unwrap());
            assert_eq!("", remainder);
        }
    }

    #[test]
    fn test_string() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample the state path.
            let expected =
                crate::state_path::test_helpers::sample_global_state_path::<CurrentNetwork>(None, &mut rng).unwrap();

            // Check the string representation.
            let candidate = format!("{expected}");
            assert_eq!(expected, StatePath::from_str(&candidate).unwrap());
            assert_eq!(STATE_PATH_PREFIX, candidate.split('1').next().unwrap());
        }
    }

    #[test]
    fn test_display() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample the state path.
            let expected =
                crate::state_path::test_helpers::sample_global_state_path::<CurrentNetwork>(None, &mut rng).unwrap();

            let candidate = expected.to_string();
            assert_eq!(format!("{expected}"), candidate);
            assert_eq!(STATE_PATH_PREFIX, candidate.split('1').next().unwrap());

            let candidate_recovered = StatePath::<CurrentNetwork>::from_str(&candidate.to_string()).unwrap();
            assert_eq!(expected, candidate_recovered);
        }
    }
}
