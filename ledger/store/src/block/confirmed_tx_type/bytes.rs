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

impl<N: Network> FromBytes for ConfirmedTxType<N> {
    /// Reads the confirmed transaction type from the buffer, either with or without checking the data.
    fn read_le_with_unchecked<R: Read>(mut reader: R, unchecked: bool) -> IoResult<Self> {
        // Read the variant.
        let variant = u8::read_le(&mut reader)?;
        // Match the variant.
        match variant {
            0 => Ok(Self::AcceptedDeploy(u32::read_le(&mut reader)?)),
            1 => Ok(Self::AcceptedExecute(u32::read_le(&mut reader)?)),
            2 => Ok(Self::RejectedDeploy(
                u32::read_le(&mut reader)?,
                Rejected::read_le_with_unchecked(&mut reader, unchecked)?,
            )),
            3 => Ok(Self::RejectedExecute(
                u32::read_le(&mut reader)?,
                Rejected::read_le_with_unchecked(&mut reader, unchecked)?,
            )),
            4.. => Err(error("Invalid confirmed transaction type variant")),
        }
    }

    /// Reads the confirmed transaction type from the buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, false)
    }

    /// Reads the confirmed transaction type from the buffer without checking the data.
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, true)
    }
}

impl<N: Network> ToBytes for ConfirmedTxType<N> {
    /// Writes the confirmed transaction type to the buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the confirmed transaction type.
        match self {
            Self::AcceptedDeploy(index) => {
                // Write the variant.
                0u8.write_le(&mut writer)?;
                // Write the index.
                index.write_le(&mut writer)
            }
            Self::AcceptedExecute(index) => {
                // Write the variant.
                1u8.write_le(&mut writer)?;
                // Write the index.
                index.write_le(&mut writer)
            }
            Self::RejectedDeploy(index, rejected) => {
                // Write the variant.
                2u8.write_le(&mut writer)?;
                // Write the index.
                index.write_le(&mut writer)?;
                // Write the rejected transaction.
                rejected.write_le(&mut writer)
            }
            Self::RejectedExecute(index, rejected) => {
                // Write the variant.
                3u8.write_le(&mut writer)?;
                // Write the index.
                index.write_le(&mut writer)?;
                // Write the rejected transaction.
                rejected.write_le(&mut writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() {
        for expected in crate::confirmed_tx_type::test_helpers::sample_confirmed_tx_types() {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, ConfirmedTxType::read_le(&expected_bytes[..]).unwrap());
            assert_eq!(expected, ConfirmedTxType::read_le_unchecked(&expected_bytes[..]).unwrap());
        }
    }
}
