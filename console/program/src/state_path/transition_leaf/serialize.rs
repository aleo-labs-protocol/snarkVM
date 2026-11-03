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

use snarkvm_utilities::DeserializeExt;

impl<N: Network> Serialize for TransitionLeaf<N> {
    /// Serializes the leaf into string or bytes.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => {
                let mut leaf = serializer.serialize_struct("TransitionLeaf", 4)?;
                leaf.serialize_field("version", &self.version)?;
                leaf.serialize_field("index", &self.index)?;
                leaf.serialize_field("variant", &self.variant)?;
                leaf.serialize_field("id", &self.id)?;
                leaf.end()
            }
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for TransitionLeaf<N> {
    /// Deserializes the leaf from a string or bytes.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                // Parse the leaf from a string into a value.
                let mut leaf = serde_json::Value::deserialize(deserializer)?;
                // Recover the leaf.
                Self::from(
                    // Retrieve the version.
                    DeserializeExt::take_from_value::<D>(&mut leaf, "version")?,
                    // Retrieve the index.
                    DeserializeExt::take_from_value::<D>(&mut leaf, "index")?,
                    // Retrieve the variant.
                    DeserializeExt::take_from_value::<D>(&mut leaf, "variant")?,
                    // Retrieve the id.
                    DeserializeExt::take_from_value::<D>(&mut leaf, "id")?,
                )
                .map_err(de::Error::custom)
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "transition leaf"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_json() -> Result<()> {
        let mut rng = TestRng::default();

        // Sample a static leaf (version 1).
        let expected = test_helpers::sample_leaf(&mut rng);

        // Serialize
        let expected_string = &expected.to_string();
        let candidate_string = serde_json::to_string(&expected)?;
        assert_eq!(expected, serde_json::from_str(&candidate_string)?);

        // Deserialize
        assert_eq!(expected, TransitionLeaf::from_str(expected_string)?);
        assert_eq!(expected, serde_json::from_str(&candidate_string)?);

        // Sample a dynamic leaf (version 2).
        let expected_dynamic = test_helpers::sample_dynamic_leaf(&mut rng);

        // Serialize
        let expected_dynamic_string = &expected_dynamic.to_string();
        let candidate_dynamic_string = serde_json::to_string(&expected_dynamic)?;
        assert_eq!(expected_dynamic, serde_json::from_str(&candidate_dynamic_string)?);

        // Deserialize
        assert_eq!(expected_dynamic, TransitionLeaf::from_str(expected_dynamic_string)?);
        assert_eq!(expected_dynamic, serde_json::from_str(&candidate_dynamic_string)?);

        Ok(())
    }

    #[test]
    fn test_bincode() -> Result<()> {
        let mut rng = TestRng::default();

        // Sample a static leaf (version 1).
        let expected = test_helpers::sample_leaf(&mut rng);

        // Serialize
        let expected_bytes = expected.to_bytes_le()?;
        let expected_bytes_with_size_encoding = bincode::serialize(&expected)?;
        assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

        // Deserialize
        assert_eq!(expected, TransitionLeaf::read_le(&expected_bytes[..])?);
        assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding[..])?);

        // Sample a dynamic leaf (version 2).
        let expected_dynamic = test_helpers::sample_dynamic_leaf(&mut rng);

        // Serialize
        let expected_dynamic_bytes = expected_dynamic.to_bytes_le()?;
        let expected_dynamic_bytes_with_size_encoding = bincode::serialize(&expected_dynamic)?;
        assert_eq!(&expected_dynamic_bytes[..], &expected_dynamic_bytes_with_size_encoding[8..]);

        // Deserialize
        assert_eq!(expected_dynamic, TransitionLeaf::read_le(&expected_dynamic_bytes[..])?);
        assert_eq!(expected_dynamic, bincode::deserialize(&expected_dynamic_bytes_with_size_encoding[..])?);

        Ok(())
    }
}
