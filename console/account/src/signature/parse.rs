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

static SIGNATURE_PREFIX: &str = "sign";

impl<N: Network> Parser for Signature<N> {
    /// Parses a string into an signature.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Prepare a parser for the Aleo signature.
        let parse_signature = recognize(pair(
            pair(tag(SIGNATURE_PREFIX), tag("1")),
            many1(terminated(one_of("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), many0(char('_')))),
        ));

        // Parse the signature from the string.
        map_res(parse_signature, |signature: &str| -> Result<_, Error> { Self::from_str(&signature.replace('_', "")) })(
            string,
        )
    }
}

impl<N: Network> FromStr for Signature<N> {
    type Err = Error;

    /// Reads in the signature string.
    fn from_str(signature: &str) -> Result<Self, Self::Err> {
        // Decode the signature string from bech32m.
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<LongBech32m>(signature)?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        if hrp.as_str() != SIGNATURE_PREFIX {
            bail!("Failed to decode signature: '{hrp}' is an invalid prefix")
        } else if data.is_empty() {
            bail!("Failed to decode signature: data field is empty")
        }
        // Decode the signature data into the signature.
        Ok(Self::read_le(&data[..])?)
    }
}

impl<N: Network> Debug for Signature<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Signature<N> {
    /// Writes the signature as a bech32m string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Convert the signature to bytes.
        let bytes = self.to_bytes_le().map_err(|_| fmt::Error)?;
        // Encode the bytes into bech32m.
        let string = bech32::encode::<LongBech32m>(bech32::Hrp::parse_unchecked(SIGNATURE_PREFIX), &bytes)
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
        assert!(Signature::<CurrentNetwork>::parse(&format!("{SIGNATURE_PREFIX}1")).is_err());
        assert!(Signature::<CurrentNetwork>::parse("").is_err());

        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a new signature.
            let expected = test_helpers::sample_signature(i, &mut rng);

            let expected = format!("{expected}");
            let (remainder, candidate) = Signature::<CurrentNetwork>::parse(&expected).unwrap();
            assert_eq!(format!("{expected}"), candidate.to_string());
            assert_eq!(SIGNATURE_PREFIX, candidate.to_string().split('1').next().unwrap());
            assert_eq!("", remainder);
        }
        Ok(())
    }

    #[test]
    fn test_string() -> Result<()> {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a new signature.
            let expected = test_helpers::sample_signature(i, &mut rng);

            // Check the string representation.
            let candidate = format!("{expected}");
            assert_eq!(expected, Signature::from_str(&candidate)?);
            assert_eq!(SIGNATURE_PREFIX, candidate.split('1').next().unwrap());
        }
        Ok(())
    }

    #[test]
    fn test_display() -> Result<()> {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a new signature.
            let expected = test_helpers::sample_signature(i, &mut rng);

            let candidate = expected.to_string();
            assert_eq!(format!("{expected}"), candidate);
            assert_eq!(SIGNATURE_PREFIX, candidate.split('1').next().unwrap());

            let candidate_recovered = Signature::<CurrentNetwork>::from_str(&candidate.to_string())?;
            assert_eq!(expected, candidate_recovered);
        }
        Ok(())
    }
}
