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

impl<N: Network> FromBytes for Input<N> {
    /// Reads the input from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let variant = Variant::read_le(&mut reader)?;
        let literal = match variant {
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
                // Read the serial number.
                let serial_number: Field<N> = FromBytes::read_le(&mut reader)?;
                // Read the tag.
                let tag: Field<N> = FromBytes::read_le(&mut reader)?;
                // Return the record.
                Self::Record(serial_number, tag)
            }
            4 => Self::ExternalRecord(FromBytes::read_le(&mut reader)?),
            5 => Self::DynamicRecord(FromBytes::read_le(&mut reader)?),
            6 => {
                // Read the serial number.
                let serial_number: Field<N> = FromBytes::read_le(&mut reader)?;
                // Read the tag.
                let tag: Field<N> = FromBytes::read_le(&mut reader)?;
                // Read the dynamic ID.
                let dynamic_id: Field<N> = FromBytes::read_le(&mut reader)?;
                // Return the record with dynamic ID.
                Self::RecordWithDynamicID(serial_number, tag, dynamic_id)
            }
            7 => {
                // Read the external record hash.
                let external_hash: Field<N> = FromBytes::read_le(&mut reader)?;
                // Read the dynamic ID.
                let dynamic_id: Field<N> = FromBytes::read_le(&mut reader)?;
                // Return the external record with dynamic ID.
                Self::ExternalRecordWithDynamicID(external_hash, dynamic_id)
            }
            8.. => return Err(error(format!("Failed to decode transition input variant {variant}"))),
        };
        Ok(literal)
    }
}

impl<N: Network> ToBytes for Input<N> {
    /// Writes the input to a buffer.
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
            Self::Record(serial_number, tag) => {
                (3 as Variant).write_le(&mut writer)?;
                serial_number.write_le(&mut writer)?;
                tag.write_le(&mut writer)
            }
            Self::ExternalRecord(input_commitment) => {
                (4 as Variant).write_le(&mut writer)?;
                input_commitment.write_le(&mut writer)
            }
            Self::DynamicRecord(hash) => {
                (5 as Variant).write_le(&mut writer)?;
                hash.write_le(&mut writer)
            }
            Self::RecordWithDynamicID(serial_number, tag, dynamic_id) => {
                (6 as Variant).write_le(&mut writer)?;
                serial_number.write_le(&mut writer)?;
                tag.write_le(&mut writer)?;
                dynamic_id.write_le(&mut writer)
            }
            Self::ExternalRecordWithDynamicID(external_hash, dynamic_id) => {
                (7 as Variant).write_le(&mut writer)?;
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
        for (_, expected) in crate::transition::input::test_helpers::sample_inputs() {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, Input::read_le(&expected_bytes[..]).unwrap());
        }
    }
}
