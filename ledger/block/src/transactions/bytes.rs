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

impl<N: Network> FromBytes for Transactions<N> {
    /// Deserialize either unchecked or checked based on the given boolean flag.
    #[inline]
    fn read_le_with_unchecked<R: Read>(mut reader: R, unchecked: bool) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid transactions version"));
        }
        // Read the number of transactions.
        let num_txs: u32 = FromBytes::read_le(&mut reader)?;
        // Ensure the number of transactions is within bounds.
        if num_txs as usize > Self::MAX_TRANSACTIONS {
            return Err(error("Failed to read transactions: too many transactions"));
        }
        // Read the transactions.
        let transactions = (0..num_txs)
            .map(|_| FromBytes::read_le_with_unchecked(&mut reader, unchecked))
            .collect::<Result<Vec<_>, _>>()?;
        // Return the transactions.
        Ok(Self::from(&transactions))
    }

    /// Reads the transactions from buffer.
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, false)
    }

    /// Reads the transactions from the buffer without performing any checks on the data.
    #[inline]
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, true)
    }
}

impl<N: Network> ToBytes for Transactions<N> {
    /// Writes the transactions to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;
        // Write the number of transactions.
        u32::try_from(self.transactions.len()).map_err(error)?.write_le(&mut writer)?;
        // Write the transactions.
        self.transactions.values().try_for_each(|transaction| transaction.write_le(&mut writer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() -> Result<()> {
        let rng = &mut TestRng::default();

        for expected in [crate::transactions::test_helpers::sample_block_transactions(rng)].into_iter() {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le()?;
            assert_eq!(expected, Transactions::read_le(&expected_bytes[..])?);
            assert_eq!(expected, Transactions::read_le_unchecked(&expected_bytes[..])?);
        }
        Ok(())
    }
}
