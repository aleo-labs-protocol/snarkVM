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

pub static SOLUTION_ID_PREFIX: &str = "solution";

impl<N: Network> FromStr for SolutionID<N> {
    type Err = Error;

    /// Reads in the solution ID string.
    fn from_str(solution_id: &str) -> Result<Self, Self::Err> {
        // Decode the solution ID string from bech32m.
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<LongBech32m>(solution_id)?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        if hrp.as_str() != SOLUTION_ID_PREFIX {
            bail!("Failed to decode solution ID: '{hrp}' is an invalid prefix")
        } else if data.is_empty() {
            bail!("Failed to decode solution ID: data field is empty")
        }
        // Decode the solution ID data into the solution ID.
        Ok(Self::read_le(&data[..])?)
    }
}

impl<N: Network> Debug for SolutionID<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for SolutionID<N> {
    /// Writes the solution ID as a bech32m string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Convert the solution ID to bytes.
        let bytes = self.to_bytes_le().map_err(|_| fmt::Error)?;
        // Encode the bytes into bech32m.
        let string = bech32::encode::<LongBech32m>(bech32::Hrp::parse_unchecked(SOLUTION_ID_PREFIX), &bytes)
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

    const ITERATIONS: u64 = 1_000;

    #[test]
    fn test_string() -> Result<()> {
        // Ensure type and empty value fails.
        assert!(SolutionID::<CurrentNetwork>::from_str(&format!("{SOLUTION_ID_PREFIX}1")).is_err());
        assert!(SolutionID::<CurrentNetwork>::from_str("").is_err());

        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new solution ID.
            let expected = SolutionID::<CurrentNetwork>::from(rng.random::<u64>());

            // Check the string representation.
            let candidate = format!("{expected}");
            assert_eq!(expected, SolutionID::from_str(&candidate)?);
            assert_eq!(SOLUTION_ID_PREFIX, candidate.split('1').next().unwrap());
        }
        Ok(())
    }

    #[test]
    fn test_display() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new solution ID.
            let expected = SolutionID::<CurrentNetwork>::from(rng.random::<u64>());

            let candidate = expected.to_string();
            assert_eq!(format!("{expected}"), candidate);
            assert_eq!(SOLUTION_ID_PREFIX, candidate.split('1').next().unwrap());

            let candidate_recovered = SolutionID::<CurrentNetwork>::from_str(&candidate.to_string())?;
            assert_eq!(expected, candidate_recovered);
        }
        Ok(())
    }
}
