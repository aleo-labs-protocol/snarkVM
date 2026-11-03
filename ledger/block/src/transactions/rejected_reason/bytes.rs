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

impl<N: Network> FromBytes for RejectedReason<N> {
    /// Reads the rejected reason from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the variant.
        let variant = u8::read_le(&mut reader)?;
        match variant {
            0 => {
                let program_id = ProgramID::<N>::read_le(&mut reader)?;
                Ok(Self::DuplicateProgramID(program_id))
            }
            1 => {
                let program_id = ProgramID::<N>::read_le(&mut reader)?;
                let edition = u16::read_le(&mut reader)?;
                let resource = Identifier::<N>::read_le(&mut reader)?;
                let index = u32::read_le(&mut reader)? as usize;
                let command = Command::<N>::read_le(&mut reader)?;
                Ok(Self::Finalize { program_id, edition, resource, index, command: Box::new(command) })
            }
            2 => {
                // Read the optional program ID and edition.
                let program_id = match u8::read_le(&mut reader)? {
                    0 => None,
                    1 => {
                        let id = ProgramID::<N>::read_le(&mut reader)?;
                        let edition = u16::read_le(&mut reader)?;
                        Some((id, edition))
                    }
                    flag => return Err(error(format!("Invalid program_id presence flag {flag}"))),
                };
                // Read the optional resource.
                let resource = match u8::read_le(&mut reader)? {
                    0 => None,
                    1 => Some(Identifier::<N>::read_le(&mut reader)?),
                    flag => return Err(error(format!("Invalid resource presence flag {flag}"))),
                };
                Ok(Self::VM(program_id, resource))
            }
            3.. => Err(error(format!("Failed to decode rejected reason variant {variant}"))),
        }
    }
}

impl<N: Network> ToBytes for RejectedReason<N> {
    /// Writes the rejected reason to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::DuplicateProgramID(program_id) => {
                0u8.write_le(&mut writer)?;
                program_id.write_le(&mut writer)
            }
            Self::Finalize { program_id, edition, resource, index, command } => {
                1u8.write_le(&mut writer)?;
                program_id.write_le(&mut writer)?;
                edition.write_le(&mut writer)?;
                resource.write_le(&mut writer)?;
                u32::try_from(*index).map_err(|_| error("Command index exceeds u32::MAX"))?.write_le(&mut writer)?;
                command.write_le(&mut writer)
            }
            Self::VM(program_id, resource) => {
                2u8.write_le(&mut writer)?;
                // Write the optional program ID and edition.
                match program_id {
                    None => 0u8.write_le(&mut writer)?,
                    Some((id, edition)) => {
                        1u8.write_le(&mut writer)?;
                        id.write_le(&mut writer)?;
                        edition.write_le(&mut writer)?;
                    }
                }
                // Write the optional resource.
                match resource {
                    None => 0u8.write_le(&mut writer),
                    Some(resource) => {
                        1u8.write_le(&mut writer)?;
                        resource.write_le(&mut writer)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_bytes() {
        for expected in test_helpers::sample_rejected_reasons::<CurrentNetwork>() {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, RejectedReason::read_le(&expected_bytes[..]).unwrap());
        }
    }
}
