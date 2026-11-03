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

impl<N: Network> Serialize for PartialSolution<N> {
    /// Serializes the partial solution to a JSON-string or buffer.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => {
                let mut partial_solution = serializer.serialize_struct("PartialSolution", 4)?;
                partial_solution.serialize_field("solution_id", &self.solution_id)?;
                partial_solution.serialize_field("epoch_hash", &self.epoch_hash)?;
                partial_solution.serialize_field("address", &self.address)?;
                partial_solution.serialize_field("counter", &self.counter)?;
                partial_solution.end()
            }
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for PartialSolution<N> {
    /// Deserializes the partial solution from a JSON-string or buffer.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                let mut partial_solution = serde_json::Value::deserialize(deserializer)?;
                let solution_id: SolutionID<N> =
                    DeserializeExt::take_from_value::<D>(&mut partial_solution, "solution_id")?;

                // Recover the partial solution.
                let partial_solution = Self::new(
                    DeserializeExt::take_from_value::<D>(&mut partial_solution, "epoch_hash")?,
                    DeserializeExt::take_from_value::<D>(&mut partial_solution, "address")?,
                    DeserializeExt::take_from_value::<D>(&mut partial_solution, "counter")?,
                )
                .map_err(de::Error::custom)?;

                // Ensure the solution ID matches.
                match solution_id == partial_solution.id() {
                    true => Ok(partial_solution),
                    false => Err(de::Error::custom(error("Mismatching solution ID, possible data corruption"))),
                }
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "solution"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{account::PrivateKey, network::MainnetV0};

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_serde_json() -> Result<()> {
        let mut rng = TestRng::default();
        let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng)?;
        let address = Address::try_from(private_key)?;

        // Sample a new partial solution.
        let expected = PartialSolution::new(rng.random(), address, u64::rand(&mut rng)).unwrap();

        // Serialize
        let expected_string = &expected.to_string();
        let candidate_string = serde_json::to_string(&expected)?;
        assert_eq!(expected, serde_json::from_str(&candidate_string)?);

        // Deserialize
        assert_eq!(expected, PartialSolution::from_str(expected_string)?);
        assert_eq!(expected, serde_json::from_str(&candidate_string)?);

        Ok(())
    }

    #[test]
    fn test_bincode() -> Result<()> {
        let mut rng = TestRng::default();
        let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng)?;
        let address = Address::try_from(private_key)?;

        // Sample a new partial solution.
        let expected = PartialSolution::new(rng.random(), address, u64::rand(&mut rng)).unwrap();

        // Serialize
        let expected_bytes = expected.to_bytes_le()?;
        let expected_bytes_with_size_encoding = bincode::serialize(&expected)?;
        assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

        // Deserialize
        assert_eq!(expected, PartialSolution::read_le(&expected_bytes[..])?);
        assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding[..])?);

        Ok(())
    }
}
