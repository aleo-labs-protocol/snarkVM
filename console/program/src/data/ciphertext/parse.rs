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

static CIPHERTEXT_PREFIX: &str = "ciphertext";

impl<N: Network> Parser for Ciphertext<N> {
    /// Parses a string into an ciphertext.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Prepare a parser for the Aleo ciphertext.
        let parse_ciphertext = recognize(pair(
            pair(tag(CIPHERTEXT_PREFIX), tag("1")),
            many1(terminated(one_of("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), many0(char('_')))),
        ));

        // Parse the ciphertext from the string.
        map_res(parse_ciphertext, |ciphertext: &str| -> Result<_, Error> {
            Self::from_str(&ciphertext.replace('_', ""))
        })(string)
    }
}

impl<N: Network> FromStr for Ciphertext<N> {
    type Err = Error;

    /// Reads in the ciphertext string.
    fn from_str(ciphertext: &str) -> Result<Self, Self::Err> {
        // Decode the ciphertext string from bech32m.
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<LongBech32m>(ciphertext)?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        if hrp.as_str() != CIPHERTEXT_PREFIX {
            bail!("Failed to decode ciphertext: '{hrp}' is an invalid prefix")
        } else if data.is_empty() {
            bail!("Failed to decode ciphertext: data field is empty")
        }
        // Decode the ciphertext data into the ciphertext.
        Ok(Self::read_le(&data[..])?)
    }
}

impl<N: Network> Debug for Ciphertext<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Ciphertext<N> {
    /// Writes the ciphertext as a bech32m string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Convert the ciphertext to bytes.
        let bytes = self.to_bytes_le().map_err(|_| fmt::Error)?;
        // Encode the bytes into bech32m.
        let string = bech32::encode::<LongBech32m>(bech32::Hrp::parse_unchecked(CIPHERTEXT_PREFIX), &bytes)
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

    const ITERATIONS: u64 = 1_000;

    #[test]
    fn test_parse() -> Result<()> {
        // Ensure type and empty value fails.
        assert!(Ciphertext::<CurrentNetwork>::parse(&format!("{CIPHERTEXT_PREFIX}1")).is_err());
        assert!(Ciphertext::<CurrentNetwork>::parse("").is_err());

        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new ciphertext.
            let ciphertext =
                Ciphertext::<CurrentNetwork>((0..100).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>());

            let expected = format!("{ciphertext}");
            let (remainder, candidate) = Ciphertext::<CurrentNetwork>::parse(&expected).unwrap();
            assert_eq!(format!("{expected}"), candidate.to_string());
            assert_eq!(CIPHERTEXT_PREFIX, candidate.to_string().split('1').next().unwrap());
            assert_eq!("", remainder);
        }
        Ok(())
    }

    #[test]
    fn test_string() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new ciphertext.
            let expected = Ciphertext::<CurrentNetwork>((0..100).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>());

            // Check the string representation.
            let candidate = format!("{expected}");
            assert_eq!(expected, Ciphertext::from_str(&candidate)?);
            assert_eq!(CIPHERTEXT_PREFIX, candidate.split('1').next().unwrap());
        }
        Ok(())
    }

    #[test]
    fn test_display() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new ciphertext.
            let expected = Ciphertext::<CurrentNetwork>((0..100).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>());

            let candidate = expected.to_string();
            assert_eq!(format!("{expected}"), candidate);
            assert_eq!(CIPHERTEXT_PREFIX, candidate.split('1').next().unwrap());

            let candidate_recovered = Ciphertext::<CurrentNetwork>::from_str(&candidate.to_string())?;
            assert_eq!(expected, candidate_recovered);
        }
        Ok(())
    }
}
