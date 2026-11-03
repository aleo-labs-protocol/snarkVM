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

impl<N: Network> FromBytes for InputID<N> {
    /// Reads the input ID from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the variant.
        let variant = u8::read_le(&mut reader)?;
        // Match the variant.
        match variant {
            // Constant input.
            0 => Ok(Self::Constant(Field::read_le(&mut reader)?)),
            // Public input.
            1 => Ok(Self::Public(Field::read_le(&mut reader)?)),
            // Private input.
            2 => Ok(Self::Private(Field::read_le(&mut reader)?)),
            // Record input.
            3 => {
                // Read the commitment.
                let commitment = Field::read_le(&mut reader)?;
                // Read the gamma value.
                let gamma = Group::read_le(&mut reader)?;
                // Read the record view key.
                let record_view_key = Field::read_le(&mut reader)?;
                // Read the serial number.
                let serial_number = Field::read_le(&mut reader)?;
                // Read the tag value.
                let tag = Field::read_le(&mut reader)?;
                // Return the record input.
                Ok(Self::Record(commitment, gamma, record_view_key, serial_number, tag))
            }
            // External record input.
            4 => Ok(Self::ExternalRecord(Field::read_le(&mut reader)?)),
            // Dynamic record input.
            5 => Ok(Self::DynamicRecord(Field::read_le(&mut reader)?)),
            // Invalid input.
            _ => Err(error("Invalid input ID variant")),
        }
    }
}

impl<N: Network> ToBytes for InputID<N> {
    /// Writes the input ID to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            // Constant input.
            Self::Constant(value) => {
                // Write the variant.
                0u8.write_le(&mut writer)?;
                // Write the value.
                value.write_le(&mut writer)
            }
            // Public input.
            Self::Public(value) => {
                // Write the variant.
                1u8.write_le(&mut writer)?;
                // Write the value.
                value.write_le(&mut writer)
            }
            // Private input.
            Self::Private(value) => {
                // Write the variant.
                2u8.write_le(&mut writer)?;
                // Write the value.
                value.write_le(&mut writer)
            }
            // Record input.
            Self::Record(commitment, gamma, record_view_key, serial_number, tag) => {
                // Write the variant.
                3u8.write_le(&mut writer)?;
                // Write the commitment.
                commitment.write_le(&mut writer)?;
                // Write the gamma value.
                gamma.write_le(&mut writer)?;
                // Write the record view key.
                record_view_key.write_le(&mut writer)?;
                // Write the serial number.
                serial_number.write_le(&mut writer)?;
                // Write the tag value.
                tag.write_le(&mut writer)
            }
            // External record input.
            Self::ExternalRecord(value) => {
                // Write the variant.
                4u8.write_le(&mut writer)?;
                // Write the value.
                value.write_le(&mut writer)
            }
            // Dynamic record input.
            Self::DynamicRecord(value) => {
                // Write the variant.
                5u8.write_le(&mut writer)?;
                // Write the value.
                value.write_le(&mut writer)
            }
        }
    }
}
