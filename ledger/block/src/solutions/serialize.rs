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

impl<N: Network> Serialize for Solutions<N> {
    /// Serializes the solutions to a JSON-string or buffer.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => {
                let mut solutions = serializer.serialize_struct("Solutions", 1 + self.solutions.is_some() as usize)?;
                solutions.serialize_field("version", &1u8)?;
                if let Some(s) = &self.solutions {
                    solutions.serialize_field("solutions", s)?;
                }
                solutions.end()
            }
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Solutions<N> {
    /// Deserializes the solutions from a JSON-string or buffer.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                // Deserialize the solutions into a JSON value.
                let mut solutions = serde_json::Value::deserialize(deserializer)?;

                // Retrieve the version.
                let version: u8 = DeserializeExt::take_from_value::<D>(&mut solutions, "version")?;
                // Ensure the version is valid.
                if version != 1 {
                    return Err(de::Error::custom(format!("Invalid solutions version ({version})")));
                }

                // Retrieve the solutions, if it exists.
                Ok(Self {
                    solutions: serde_json::from_value(
                        solutions.get_mut("solutions").unwrap_or(&mut serde_json::Value::Null).take(),
                    )
                    .map_err(de::Error::custom)?,
                })
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "solutions"),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use console::account::{Address, PrivateKey};
    use snarkvm_ledger_puzzle::{PartialSolution, Solution};

    type CurrentNetwork = console::network::MainnetV0;

    pub(crate) fn sample_solutions(rng: &mut TestRng) -> Solutions<CurrentNetwork> {
        // Sample a new solutions.
        let mut solutions = vec![];
        for _ in 0..rng.random_range(1..=CurrentNetwork::MAX_SOLUTIONS) {
            let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
            let address = Address::try_from(private_key).unwrap();
            let partial_solution = PartialSolution::new(rng.random(), address, u64::rand(rng)).unwrap();
            solutions.push(Solution::new(partial_solution, u64::rand(rng)));
        }
        Solutions::new(PuzzleSolutions::new(solutions).unwrap()).unwrap()
    }

    #[test]
    fn test_serde_json() -> Result<()> {
        let rng = &mut TestRng::default();

        // Sample a new solutions.
        let expected = sample_solutions(rng);

        // Serialize
        let expected_string = &expected.to_string();
        let candidate_string = serde_json::to_string(&expected)?;
        assert_eq!(expected, serde_json::from_str(&candidate_string)?);

        // Deserialize
        assert_eq!(expected, Solutions::from_str(expected_string)?);
        assert_eq!(expected, serde_json::from_str(&candidate_string)?);

        Ok(())
    }

    #[test]
    fn test_bincode() -> Result<()> {
        let rng = &mut TestRng::default();

        // Sample a new solutions.
        let expected = sample_solutions(rng);

        // Serialize
        let expected_bytes = expected.to_bytes_le()?;
        let expected_bytes_with_size_encoding = bincode::serialize(&expected)?;
        assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

        // Deserialize
        assert_eq!(expected, Solutions::read_le(&expected_bytes[..])?);
        assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding[..])?);

        Ok(())
    }
}
