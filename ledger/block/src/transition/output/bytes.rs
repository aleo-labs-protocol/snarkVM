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

/// Reads record fields shared by Record and RecordWithDynamicID variants.
/// Returns (commitment, checksum, record_ciphertext, sender_ciphertext).
#[allow(clippy::type_complexity)]
fn read_record_fields<N: Network, R: Read>(
    reader: &mut R,
) -> IoResult<(Field<N>, Field<N>, Option<Record<N, Ciphertext<N>>>, Option<Field<N>>)> {
    // Read the commitment.
    let commitment = FromBytes::read_le(&mut *reader)?;
    // Read the checksum.
    let checksum = FromBytes::read_le(&mut *reader)?;
    // Read the record ciphertext.
    let record_ciphertext_exists: bool = FromBytes::read_le(&mut *reader)?;
    let record_ciphertext: Option<Record<N, _>> = match record_ciphertext_exists {
        true => Some(FromBytes::read_le(&mut *reader)?),
        false => None,
    };
    // If the record version is Version 1 or higher, read the sender ciphertext.
    let sender_ciphertext = match &record_ciphertext {
        Some(record) => match record.version().is_zero() {
            true => None,
            false => {
                // Read the sender ciphertext version.
                let sender_ciphertext_version: u8 = FromBytes::read_le(&mut *reader)?;
                // Ensure the sender ciphertext version is 0.
                if sender_ciphertext_version != 0 {
                    return Err(error(format!(
                        "Failed to decode sender ciphertext version {sender_ciphertext_version}"
                    )));
                }
                // Read the sender ciphertext.
                Some(FromBytes::read_le(&mut *reader)?)
            }
        },
        None => None,
    };
    Ok((commitment, checksum, record_ciphertext, sender_ciphertext))
}

/// Writes record fields shared by Record and RecordWithDynamicID variants.
fn write_record_fields<N: Network, W: Write>(
    writer: &mut W,
    commitment: &Field<N>,
    checksum: &Field<N>,
    record_ciphertext: &Option<Record<N, Ciphertext<N>>>,
    sender_ciphertext: &Option<Field<N>>,
) -> IoResult<()> {
    // Write the commitment.
    commitment.write_le(&mut *writer)?;
    // Write the checksum.
    checksum.write_le(&mut *writer)?;
    // Write the record ciphertext.
    match record_ciphertext {
        Some(record) => {
            true.write_le(&mut *writer)?;
            record.write_le(&mut *writer)?;
            // If the record version is Version 1 or higher, write the sender ciphertext.
            if !record.version().is_zero() {
                // Write the sender ciphertext version.
                0u8.write_le(&mut *writer)?;
                // Write the sender ciphertext.
                match sender_ciphertext {
                    Some(sender) => sender.write_le(&mut *writer)?,
                    None => {
                        return Err(error("Failed to encode sender ciphertext for non-zero version record"));
                    }
                }
            }
        }
        None => false.write_le(&mut *writer)?,
    }
    Ok(())
}

impl<N: Network> FromBytes for Output<N> {
    /// Reads the output from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let index = Variant::read_le(&mut reader)?;
        let literal = match index {
            0 => {
                let plaintext_hash: Field<N> = FromBytes::read_le(&mut reader)?;
                let plaintext_exists: bool = FromBytes::read_le(&mut reader)?;
                let plaintext = match plaintext_exists {
                    true => Some(FromBytes::read_le(&mut reader)?),
                    false => None,
                };

                Self::Constant(plaintext_hash, plaintext)
            }
            1 => {
                let plaintext_hash: Field<N> = FromBytes::read_le(&mut reader)?;
                let plaintext_exists: bool = FromBytes::read_le(&mut reader)?;
                let plaintext = match plaintext_exists {
                    true => Some(FromBytes::read_le(&mut reader)?),
                    false => None,
                };
                Self::Public(plaintext_hash, plaintext)
            }
            2 => {
                let ciphertext_hash: Field<N> = FromBytes::read_le(&mut reader)?;
                let ciphertext_exists: bool = FromBytes::read_le(&mut reader)?;
                let ciphertext = match ciphertext_exists {
                    true => Some(FromBytes::read_le(&mut reader)?),
                    false => None,
                };
                Self::Private(ciphertext_hash, ciphertext)
            }
            3 => {
                let (commitment, checksum, record_ciphertext, sender_ciphertext) = read_record_fields(&mut reader)?;
                Self::Record(commitment, checksum, record_ciphertext, sender_ciphertext)
            }
            4 => {
                let commitment = FromBytes::read_le(&mut reader)?;
                Self::ExternalRecord(commitment)
            }
            5 => {
                let future_hash: Field<N> = FromBytes::read_le(&mut reader)?;
                let future_exists: bool = FromBytes::read_le(&mut reader)?;
                let future = match future_exists {
                    true => Some(FromBytes::read_le(&mut reader)?),
                    false => None,
                };
                Self::Future(future_hash, future)
            }
            6 => {
                let commitment = FromBytes::read_le(&mut reader)?;
                Self::DynamicRecord(commitment)
            }
            7 => {
                let (commitment, checksum, record_ciphertext, sender_ciphertext) = read_record_fields(&mut reader)?;
                // Read the dynamic ID.
                let dynamic_id: Field<N> = FromBytes::read_le(&mut reader)?;
                Self::RecordWithDynamicID(commitment, checksum, record_ciphertext, sender_ciphertext, dynamic_id)
            }
            8 => {
                // Read the external record hash.
                let external_hash: Field<N> = FromBytes::read_le(&mut reader)?;
                // Read the dynamic ID.
                let dynamic_id: Field<N> = FromBytes::read_le(&mut reader)?;
                // Return the external record with dynamic ID.
                Self::ExternalRecordWithDynamicID(external_hash, dynamic_id)
            }
            9.. => return Err(error(format!("Failed to decode output variant {index}"))),
        };
        Ok(literal)
    }
}

impl<N: Network> ToBytes for Output<N> {
    /// Writes the output to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Constant(plaintext_hash, plaintext) => {
                (0 as Variant).write_le(&mut writer)?;
                plaintext_hash.write_le(&mut writer)?;
                match plaintext {
                    Some(plaintext) => {
                        true.write_le(&mut writer)?;
                        plaintext.write_le(&mut writer)
                    }
                    None => false.write_le(&mut writer),
                }
            }
            Self::Public(plaintext_hash, plaintext) => {
                (1 as Variant).write_le(&mut writer)?;
                plaintext_hash.write_le(&mut writer)?;
                match plaintext {
                    Some(plaintext) => {
                        true.write_le(&mut writer)?;
                        plaintext.write_le(&mut writer)
                    }
                    None => false.write_le(&mut writer),
                }
            }
            Self::Private(ciphertext_hash, ciphertext) => {
                (2 as Variant).write_le(&mut writer)?;
                ciphertext_hash.write_le(&mut writer)?;
                match ciphertext {
                    Some(ciphertext) => {
                        true.write_le(&mut writer)?;
                        ciphertext.write_le(&mut writer)
                    }
                    None => false.write_le(&mut writer),
                }
            }
            Self::Record(commitment, checksum, record_ciphertext, sender_ciphertext) => {
                (3 as Variant).write_le(&mut writer)?;
                write_record_fields(&mut writer, commitment, checksum, record_ciphertext, sender_ciphertext)
            }
            Self::ExternalRecord(commitment) => {
                (4 as Variant).write_le(&mut writer)?;
                commitment.write_le(&mut writer)
            }
            Self::Future(future_hash, future) => {
                (5 as Variant).write_le(&mut writer)?;
                future_hash.write_le(&mut writer)?;
                match future {
                    Some(future) => {
                        true.write_le(&mut writer)?;
                        future.write_le(&mut writer)
                    }
                    None => false.write_le(&mut writer),
                }
            }
            Self::DynamicRecord(commitment) => {
                (6 as Variant).write_le(&mut writer)?;
                commitment.write_le(&mut writer)
            }
            Self::RecordWithDynamicID(commitment, checksum, record_ciphertext, sender_ciphertext, dynamic_id) => {
                (7 as Variant).write_le(&mut writer)?;
                write_record_fields(&mut writer, commitment, checksum, record_ciphertext, sender_ciphertext)?;
                // Write the dynamic ID.
                dynamic_id.write_le(&mut writer)
            }
            Self::ExternalRecordWithDynamicID(external_hash, dynamic_id) => {
                (8 as Variant).write_le(&mut writer)?;
                external_hash.write_le(&mut writer)?;
                dynamic_id.write_le(&mut writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() {
        for (_, expected) in crate::transition::output::test_helpers::sample_outputs() {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, Output::read_le(&expected_bytes[..]).unwrap());
        }
    }
}
