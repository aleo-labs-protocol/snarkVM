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

impl<N: Network> FromBytes for ConfirmedTransaction<N> {
    /// Reads the confirmed transaction from a buffer, either with or without checking the data.
    fn read_le_with_unchecked<R: Read>(mut reader: R, unchecked: bool) -> IoResult<Self> {
        let variant = u8::read_le(&mut reader)?;
        match variant {
            0 => {
                // Read the index.
                let index = u32::read_le(&mut reader)?;
                // Read the transaction.
                let transaction = Transaction::<N>::read_le_with_unchecked(&mut reader, unchecked)?;
                // Read the number of finalize operations.
                let num_finalize = NumFinalizeSize::read_le(&mut reader)?;
                // Ensure the number of finalize operations is within bounds.
                if num_finalize as usize > N::MAX_COMMANDS {
                    return Err(error(format!(
                        "ConfirmedTransaction (from 'read_le') has too many finalize operations ({} > {})",
                        num_finalize,
                        N::MAX_COMMANDS
                    )));
                }
                // Read the finalize operations.
                let finalize =
                    (0..num_finalize).map(|_| FromBytes::read_le(&mut reader)).collect::<Result<Vec<_>, _>>()?;
                // Return the confirmed transaction.
                Self::accepted_deploy(index, transaction, finalize).map_err(error)
            }
            1 => {
                // Read the index.
                let index = u32::read_le(&mut reader)?;
                // Read the transaction.
                let transaction = Transaction::<N>::read_le_with_unchecked(&mut reader, unchecked)?;
                // Read the number of finalize operations.
                let num_finalize = NumFinalizeSize::read_le(&mut reader)?;
                // Ensure the number of finalize operations is within bounds.
                if num_finalize as usize > N::MAX_COMMANDS {
                    return Err(error(format!(
                        "ConfirmedTransaction (from 'read_le') has too many finalize operations ({} > {})",
                        num_finalize,
                        N::MAX_COMMANDS
                    )));
                }
                // Read the finalize operations.
                let finalize =
                    (0..num_finalize).map(|_| FromBytes::read_le(&mut reader)).collect::<Result<Vec<_>, _>>()?;
                // Return the confirmed transaction.
                Self::accepted_execute(index, transaction, finalize).map_err(error)
            }
            2 => {
                // Read the index.
                let index = u32::read_le(&mut reader)?;
                // Read the transaction.
                let transaction = Transaction::<N>::read_le_with_unchecked(&mut reader, unchecked)?;
                // Read the rejected deployment.
                let rejected = Rejected::<N>::read_le_with_unchecked(&mut reader, unchecked)?;
                // Read the number of finalize operations.
                let num_finalize = NumFinalizeSize::read_le(&mut reader)?;
                // Ensure the number of finalize operations is within bounds.
                if num_finalize as usize > N::MAX_COMMANDS {
                    return Err(error(format!(
                        "ConfirmedTransaction (from 'read_le') has too many finalize operations ({} > {})",
                        num_finalize,
                        N::MAX_COMMANDS
                    )));
                }
                // Read the finalize operations.
                let finalize =
                    (0..num_finalize).map(|_| FromBytes::read_le(&mut reader)).collect::<Result<Vec<_>, _>>()?;
                // Return the confirmed transaction.
                Self::rejected_deploy(index, transaction, rejected, finalize).map_err(error)
            }
            3 => {
                // Read the index.
                let index = u32::read_le(&mut reader)?;
                // Read the transaction.
                let transaction = Transaction::<N>::read_le_with_unchecked(&mut reader, unchecked)?;
                // Read the rejected execution.
                let rejected = Rejected::<N>::read_le_with_unchecked(&mut reader, unchecked)?;
                // Read the number of finalize operations.
                let num_finalize = NumFinalizeSize::read_le(&mut reader)?;
                // Ensure the number of finalize operations is within bounds.
                if num_finalize as usize > N::MAX_COMMANDS {
                    return Err(error(format!(
                        "ConfirmedTransaction (from 'read_le') has too many finalize operations ({} > {})",
                        num_finalize,
                        N::MAX_COMMANDS
                    )));
                }
                // Read the finalize operations.
                let finalize =
                    (0..num_finalize).map(|_| FromBytes::read_le(&mut reader)).collect::<Result<Vec<_>, _>>()?;
                // Return the confirmed transaction.
                Self::rejected_execute(index, transaction, rejected, finalize).map_err(error)
            }
            4.. => Err(error(format!("Failed to decode confirmed transaction variant {variant}"))),
        }
    }

    /// Reads the confirmed transaction from a buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, false)
    }

    /// Reads the confirmed transaction from a buffer without checking the data.
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, true)
    }
}

impl<N: Network> ToBytes for ConfirmedTransaction<N> {
    /// Writes the confirmed transaction to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::AcceptedDeploy(index, transaction, finalize) => {
                // Write the variant.
                0u8.write_le(&mut writer)?;
                // Write the index.
                index.write_le(&mut writer)?;
                // Write the transaction.
                transaction.write_le(&mut writer)?;
                // Write the number of finalize operations.
                NumFinalizeSize::try_from(finalize.len()).map_err(error)?.write_le(&mut writer)?;
                // Write the finalize operations.
                finalize.iter().try_for_each(|finalize| finalize.write_le(&mut writer))
            }
            Self::AcceptedExecute(index, transaction, finalize) => {
                // Write the variant.
                1u8.write_le(&mut writer)?;
                // Write the index.
                index.write_le(&mut writer)?;
                // Write the transaction.
                transaction.write_le(&mut writer)?;
                // Write the number of finalize operations.
                NumFinalizeSize::try_from(finalize.len()).map_err(error)?.write_le(&mut writer)?;
                // Write the finalize operations.
                finalize.iter().try_for_each(|finalize| finalize.write_le(&mut writer))
            }
            Self::RejectedDeploy(index, transaction, rejected, finalize) => {
                // Write the variant.
                2u8.write_le(&mut writer)?;
                // Write the index.
                index.write_le(&mut writer)?;
                // Write the transaction.
                transaction.write_le(&mut writer)?;
                // Write the rejected deployment.
                rejected.write_le(&mut writer)?;
                // Write the number of finalize operations.
                NumFinalizeSize::try_from(finalize.len()).map_err(error)?.write_le(&mut writer)?;
                // Write the finalize operations.
                finalize.iter().try_for_each(|finalize| finalize.write_le(&mut writer))
            }
            Self::RejectedExecute(index, transaction, rejected, finalize) => {
                // Write the variant.
                3u8.write_le(&mut writer)?;
                // Write the index.
                index.write_le(&mut writer)?;
                // Write the transaction.
                transaction.write_le(&mut writer)?;
                // Write the rejected execution.
                rejected.write_le(&mut writer)?;
                // Write the number of finalize operations.
                NumFinalizeSize::try_from(finalize.len()).map_err(error)?.write_le(&mut writer)?;
                // Write the finalize operations.
                finalize.iter().try_for_each(|finalize| finalize.write_le(&mut writer))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() {
        for expected in crate::transactions::confirmed::test_helpers::sample_confirmed_transactions() {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, ConfirmedTransaction::read_le(&expected_bytes[..]).unwrap());
            assert_eq!(expected, ConfirmedTransaction::read_le_unchecked(&expected_bytes[..]).unwrap());
        }
    }
}
