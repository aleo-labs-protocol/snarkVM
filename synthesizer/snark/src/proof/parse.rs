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

static PROOF_PREFIX: &str = "proof";

impl<N: Network> Parser for Proof<N> {
    /// Parses a string into an proof.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Prepare a parser for the Aleo proof.
        let parse_proof = recognize(pair(
            pair(tag(PROOF_PREFIX), tag("1")),
            many1(terminated(one_of("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), many0(char('_')))),
        ));

        // Parse the proof from the string.
        map_res(parse_proof, |proof: &str| -> Result<_, Error> { Self::from_str(&proof.replace('_', "")) })(string)
    }
}

impl<N: Network> FromStr for Proof<N> {
    type Err = Error;

    /// Reads in the proof string.
    fn from_str(proof: &str) -> Result<Self, Self::Err> {
        // Decode the proof string from bech32m.
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<LongBech32m>(proof)?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        if hrp.as_str() != PROOF_PREFIX {
            bail!("Failed to decode proof: '{hrp}' is an invalid prefix")
        } else if data.is_empty() {
            bail!("Failed to decode proof: data field is empty")
        }
        // Decode the proof data into the proof.
        Ok(Self::read_le(&data[..])?)
    }
}

impl<N: Network> Debug for Proof<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Proof<N> {
    /// Writes the proof as a bech32m string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Convert the proof to bytes.
        let bytes = self.to_bytes_le().map_err(|_| fmt::Error)?;
        // Encode the bytes into bech32m.
        let string = bech32::encode::<LongBech32m>(bech32::Hrp::parse_unchecked(PROOF_PREFIX), &bytes)
            .map_err(|_| fmt::Error)?;
        // Output the string.
        Display::fmt(&string, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() -> Result<()> {
        // Ensure type and empty value fails.
        assert!(Proof::<CurrentNetwork>::parse(&format!("{PROOF_PREFIX}1")).is_err());
        assert!(Proof::<CurrentNetwork>::parse("").is_err());

        // Sample the proof.
        let proof = crate::test_helpers::sample_proof();

        // Check the proof parsing.
        let expected = format!("{proof}");
        let (remainder, candidate) = Proof::<CurrentNetwork>::parse(&expected).unwrap();
        assert_eq!(format!("{expected}"), candidate.to_string());
        assert_eq!(PROOF_PREFIX, candidate.to_string().split('1').next().unwrap());
        assert_eq!("", remainder);
        Ok(())
    }

    #[test]
    fn test_string() -> Result<()> {
        // Sample the proof.
        let expected = crate::test_helpers::sample_proof();

        // Check the string representation.
        let candidate = format!("{expected}");
        assert_eq!(expected, Proof::from_str(&candidate)?);
        assert_eq!(PROOF_PREFIX, candidate.split('1').next().unwrap());

        Ok(())
    }

    #[test]
    fn test_display() -> Result<()> {
        // Sample the proof.
        let expected = crate::test_helpers::sample_proof();

        let candidate = expected.to_string();
        assert_eq!(format!("{expected}"), candidate);
        assert_eq!(PROOF_PREFIX, candidate.split('1').next().unwrap());

        let candidate_recovered = Proof::<CurrentNetwork>::from_str(&candidate)?;
        assert_eq!(expected, candidate_recovered);

        Ok(())
    }
}
