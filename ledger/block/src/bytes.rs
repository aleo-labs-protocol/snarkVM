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

impl<N: Network> Block<N> {
    /// Reads the block either with or without checking the data, decoding each compute key of
    /// its authority only if `cache` holds no earlier decode of the same bytes.
    pub fn read_le_with_cache<R: Read>(
        mut reader: R,
        unchecked: bool,
        cache: &mut ComputeKeyCache<N>,
    ) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid block version"));
        }

        // Read the block hash.
        let block_hash: N::BlockHash = FromBytes::read_le_with_unchecked(&mut reader, unchecked)?;
        // Read the previous block hash.
        let previous_hash = FromBytes::read_le_with_unchecked(&mut reader, unchecked)?;
        // Read the header.
        let header = FromBytes::read_le_with_unchecked(&mut reader, unchecked)?;

        // Read the authority.
        let authority = Authority::<N>::read_le_with_cache(&mut reader, unchecked, cache)?;

        // Read the ratifications.
        let ratifications = Ratifications::read_le_with_unchecked(&mut reader, unchecked)?;

        // Read the solutions.
        let solutions: Solutions<N> = FromBytes::read_le_with_unchecked(&mut reader, unchecked)?;

        // Read the number of aborted solution IDs.
        let num_aborted_solutions = u32::read_le(&mut reader)?;
        // Ensure the number of aborted solutions IDs is within bounds (this is an early safety check).
        if num_aborted_solutions as usize > Solutions::<N>::max_aborted_solutions() {
            return Err(error("Invalid number of aborted solutions IDs in the block"));
        }
        // Read the aborted solution IDs.
        let mut aborted_solution_ids = Vec::with_capacity(num_aborted_solutions as usize);
        for _ in 0..num_aborted_solutions {
            aborted_solution_ids.push(FromBytes::read_le_with_unchecked(&mut reader, unchecked)?);
        }

        // Read the transactions.
        let transactions = FromBytes::read_le_with_unchecked(&mut reader, unchecked)?;

        // Read the number of aborted transaction IDs.
        let num_aborted_transactions = u32::read_le(&mut reader)?;
        // Ensure the number of aborted transaction IDs is within bounds (this is an early safety check).
        if num_aborted_transactions as usize > Transactions::<N>::max_aborted_transactions() {
            return Err(error("Invalid number of aborted transaction IDs in the block"));
        }
        // Read the aborted transaction IDs.
        let mut aborted_transaction_ids = Vec::with_capacity(num_aborted_transactions as usize);
        for _ in 0..num_aborted_transactions {
            aborted_transaction_ids.push(FromBytes::read_le_with_unchecked(&mut reader, unchecked)?);
        }

        // Construct the block.
        let block = if unchecked {
            Self::from_unchecked(
                block_hash,
                previous_hash,
                header,
                authority,
                ratifications,
                solutions,
                aborted_solution_ids,
                transactions,
                aborted_transaction_ids,
            )
        } else {
            Self::from(
                previous_hash,
                header,
                authority,
                ratifications,
                solutions,
                aborted_solution_ids,
                transactions,
                aborted_transaction_ids,
            )
        }
        .map_err(error)?;

        // Ensure the block hash matches.
        match block_hash == block.hash() {
            true => Ok(block),
            false => Err(error("Mismatching block hash, possible data corruption")),
        }
    }
}

impl<N: Network> FromBytes for Block<N> {
    /// Read the block either with or without checking the data.
    fn read_le_with_unchecked<R: Read>(reader: R, unchecked: bool) -> IoResult<Self> {
        Self::read_le_with_cache(reader, unchecked, &mut ComputeKeyCache::default())
    }

    /// Reads the block from the buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, false)
    }

    // Reads the block from the buffer without any checks on the data.
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, true)
    }
}

impl<N: Network> ToBytes for Block<N> {
    /// Writes the block to the buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;

        // Write the block hash.
        self.block_hash.write_le(&mut writer)?;
        // Write the previous block hash.
        self.previous_hash.write_le(&mut writer)?;
        // Write the header.
        self.header.write_le(&mut writer)?;

        // Write the authority.
        self.authority.write_le(&mut writer)?;

        // Write the ratifications.
        self.ratifications.write_le(&mut writer)?;

        // Write the solutions.
        self.solutions.write_le(&mut writer)?;

        // Write the aborted solution IDs.
        (u32::try_from(self.aborted_solution_ids.len()).map_err(error))?.write_le(&mut writer)?;
        self.aborted_solution_ids.write_le(&mut writer)?;

        // Write the transactions.
        self.transactions.write_le(&mut writer)?;

        // Write the aborted transaction IDs.
        (u32::try_from(self.aborted_transaction_ids.len()).map_err(error))?.write_le(&mut writer)?;
        self.aborted_transaction_ids.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_bytes() -> Result<()> {
        let rng = &mut TestRng::default();

        for expected in [crate::test_helpers::sample_genesis_block(rng)].into_iter() {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le()?;
            assert_eq!(expected, Block::read_le(&expected_bytes[..])?);
            assert_eq!(expected, Block::read_le_unchecked(&expected_bytes[..])?);
        }
        Ok(())
    }

    #[test]
    fn test_genesis_bytes() -> Result<()> {
        // Load the genesis block.
        let genesis_block = Block::<CurrentNetwork>::read_le(CurrentNetwork::genesis_bytes()).unwrap();

        // Check the byte representation.
        let expected_bytes = genesis_block.to_bytes_le()?;
        assert_eq!(genesis_block, Block::read_le(&expected_bytes[..])?);
        assert_eq!(genesis_block, Block::read_le_unchecked(&expected_bytes[..])?);

        // A cache shared across reads gives the same block in both modes.
        let mut cache = ComputeKeyCache::default();
        for unchecked in [false, true, false, true] {
            let block = Block::read_le_with_cache(&expected_bytes[..], unchecked, &mut cache)?;
            assert_eq!(genesis_block, block);
            assert_eq!(expected_bytes, block.to_bytes_le()?);
        }
        assert_eq!(cache.len(), 1);

        Ok(())
    }

    #[test]
    fn test_bincode() -> Result<()> {
        // Load the genesis block.
        let genesis_block = Block::<CurrentNetwork>::read_le(CurrentNetwork::genesis_bytes()).unwrap();

        let bincode_data = bincode::serialize(&genesis_block)?;
        let block = bincode::deserialize(&bincode_data)?;

        assert_eq!(genesis_block, block);

        Ok(())
    }
}
