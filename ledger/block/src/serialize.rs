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

impl<N: Network> Serialize for Block<N> {
    /// Serializes the block to a JSON-string or buffer.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => {
                let mut block = serializer.serialize_struct("Block", 9)?;
                block.serialize_field("block_hash", &self.block_hash)?;
                block.serialize_field("previous_hash", &self.previous_hash)?;
                block.serialize_field("header", &self.header)?;
                block.serialize_field("authority", &self.authority)?;
                block.serialize_field("ratifications", &self.ratifications)?;
                block.serialize_field("solutions", &self.solutions)?;
                block.serialize_field("aborted_solution_ids", &self.aborted_solution_ids)?;
                block.serialize_field("transactions", &self.transactions)?;
                block.serialize_field("aborted_transaction_ids", &self.aborted_transaction_ids)?;
                block.end()
            }
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Block<N> {
    /// Deserializes the block from a JSON-string or buffer.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let mut block = serde_json::Value::deserialize(deserializer)?;
            let block_hash: N::BlockHash = DeserializeExt::take_from_value::<D>(&mut block, "block_hash")?;

            // Recover the block.
            let block = Self::from(
                DeserializeExt::take_from_value::<D>(&mut block, "previous_hash")?,
                DeserializeExt::take_from_value::<D>(&mut block, "header")?,
                DeserializeExt::take_from_value::<D>(&mut block, "authority")?,
                DeserializeExt::take_from_value::<D>(&mut block, "ratifications")?,
                DeserializeExt::take_from_value::<D>(&mut block, "solutions")?,
                DeserializeExt::take_from_value::<D>(&mut block, "aborted_solution_ids")?,
                DeserializeExt::take_from_value::<D>(&mut block, "transactions")?,
                DeserializeExt::take_from_value::<D>(&mut block, "aborted_transaction_ids")?,
            )
            .map_err(de::Error::custom)?;

            // Ensure the block hash matches.
            match block_hash == block.hash() {
                true => Ok(block),
                false => Err(de::Error::custom(error("Mismatching block hash, possible data corruption"))),
            }
        } else {
            FromBytesUncheckedDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "block")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_json() -> Result<()> {
        let rng = &mut TestRng::default();

        for expected in [crate::test_helpers::sample_genesis_block(rng)].into_iter() {
            // Serialize
            let expected_string = &expected.to_string();
            let candidate_string = serde_json::to_string(&expected)?;

            // Deserialize
            assert_eq!(expected, Block::from_str(expected_string)?);
            assert_eq!(expected, serde_json::from_str(&candidate_string)?);
        }
        Ok(())
    }

    #[test]
    fn test_bincode() -> Result<()> {
        let rng = &mut TestRng::default();

        for expected in [crate::test_helpers::sample_genesis_block(rng)].into_iter() {
            // Serialize
            let expected_bytes = expected.to_bytes_le()?;
            let expected_bytes_with_size_encoding = bincode::serialize(&expected)?;
            assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

            // Deserialize
            assert_eq!(expected, Block::read_le(&expected_bytes[..])?);
            assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding[..])?);
        }
        Ok(())
    }

    #[test]
    fn test_genesis_serde_json() -> Result<()> {
        // Load the genesis block.
        let Some(genesis_block) = crate::test_helpers::shipped_genesis_block() else { return Ok(()) };

        // Serialize
        let expected_string = &genesis_block.to_string();
        let candidate_string = serde_json::to_string(&genesis_block)?;

        // Deserialize
        assert_eq!(genesis_block, Block::from_str(expected_string)?);
        assert_eq!(genesis_block, serde_json::from_str(&candidate_string)?);

        Ok(())
    }

    #[test]
    fn test_genesis_bincode() -> Result<()> {
        // Load the genesis block.
        let Some(genesis_block) = crate::test_helpers::shipped_genesis_block() else { return Ok(()) };

        // Serialize
        let expected_bytes = genesis_block.to_bytes_le()?;
        let expected_bytes_with_size_encoding = bincode::serialize(&genesis_block)?;
        assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

        // Deserialize
        assert_eq!(genesis_block, Block::read_le(&expected_bytes[..])?);
        assert_eq!(genesis_block, bincode::deserialize(&expected_bytes_with_size_encoding[..])?);

        Ok(())
    }
}
