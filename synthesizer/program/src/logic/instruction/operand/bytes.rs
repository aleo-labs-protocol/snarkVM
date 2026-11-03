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

impl<N: Network> FromBytes for Operand<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        match u8::read_le(&mut reader)? {
            0 => Ok(Self::Literal(Literal::read_le(&mut reader)?)),
            1 => Ok(Self::Register(Register::read_le(&mut reader)?)),
            2 => Ok(Self::ProgramID(ProgramID::read_le(&mut reader)?)),
            3 => Ok(Self::Signer),
            4 => Ok(Self::Caller),
            5 => Ok(Self::BlockHeight),
            6 => Ok(Self::NetworkID),
            7 => {
                // Read the program ID.
                let program_id = match u8::read_le(&mut reader)? {
                    0 => None,
                    1 => Some(ProgramID::read_le(&mut reader)?),
                    variant => return Err(error(format!("Invalid program ID variant '{variant}' for the checksum"))),
                };
                Ok(Self::Checksum(program_id))
            }
            8 => {
                // Read the program ID.
                let program_id = match u8::read_le(&mut reader)? {
                    0 => None,
                    1 => Some(ProgramID::read_le(&mut reader)?),
                    variant => return Err(error(format!("Invalid program ID variant '{variant}' for the edition"))),
                };
                Ok(Self::Edition(program_id))
            }
            9 => {
                // Read the program ID.
                let program_id = match u8::read_le(&mut reader)? {
                    0 => None,
                    1 => Some(ProgramID::read_le(&mut reader)?),
                    variant => return Err(error(format!("Invalid program ID variant '{variant}' for the owner"))),
                };
                Ok(Self::ProgramOwner(program_id))
            }
            10 => Ok(Self::BlockTimestamp),
            11 => Ok(Self::AleoGenerator),
            12 => {
                let index_exists: bool = FromBytes::read_le(&mut reader)?;
                match index_exists {
                    true => {
                        let index: U32<N> = FromBytes::read_le(&mut reader)?;
                        Ok(Self::AleoGeneratorPowers(Some(index)))
                    }
                    false => Ok(Self::AleoGeneratorPowers(None)),
                }
            }
            13 => {
                // Read the program ID.
                let program_id = match u8::read_le(&mut reader)? {
                    0 => None,
                    1 => Some(ProgramID::read_le(&mut reader)?),
                    variant => {
                        return Err(error(format!(
                            "Invalid program ID variant '{variant}' for the component checksum"
                        )));
                    }
                };
                // Read the component name.
                let name = Identifier::read_le(&mut reader)?;
                Ok(Self::ComponentChecksum(program_id, name))
            }
            variant => Err(error(format!("Failed to deserialize operand variant {variant}"))),
        }
    }
}

impl<N: Network> ToBytes for Operand<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Literal(literal) => {
                0u8.write_le(&mut writer)?;
                literal.write_le(&mut writer)
            }
            Self::Register(register) => {
                1u8.write_le(&mut writer)?;
                register.write_le(&mut writer)
            }
            Self::ProgramID(program_id) => {
                2u8.write_le(&mut writer)?;
                program_id.write_le(&mut writer)
            }
            Self::Signer => 3u8.write_le(&mut writer),
            Self::Caller => 4u8.write_le(&mut writer),
            Self::BlockHeight => 5u8.write_le(&mut writer),
            Self::NetworkID => 6u8.write_le(&mut writer),
            Self::Checksum(program_id) => {
                7u8.write_le(&mut writer)?;
                // Write the program ID.
                match program_id {
                    None => 0u8.write_le(&mut writer),
                    Some(program_id) => {
                        1u8.write_le(&mut writer)?;
                        program_id.write_le(&mut writer)
                    }
                }
            }
            Self::Edition(program_id) => {
                8u8.write_le(&mut writer)?;
                // Write the program ID.
                match program_id {
                    None => 0u8.write_le(&mut writer),
                    Some(program_id) => {
                        1u8.write_le(&mut writer)?;
                        program_id.write_le(&mut writer)
                    }
                }
            }
            Self::ProgramOwner(program_id) => {
                9u8.write_le(&mut writer)?;
                // Write the program ID.
                match program_id {
                    None => 0u8.write_le(&mut writer),
                    Some(program_id) => {
                        1u8.write_le(&mut writer)?;
                        program_id.write_le(&mut writer)
                    }
                }
            }
            Self::BlockTimestamp => 10u8.write_le(&mut writer),
            Self::AleoGenerator => 11u8.write_le(&mut writer),
            Self::AleoGeneratorPowers(index) => {
                12u8.write_le(&mut writer)?;
                // Write the index if it is present.
                match index {
                    Some(index) => {
                        true.write_le(&mut writer)?;
                        index.write_le(&mut writer)
                    }
                    None => false.write_le(&mut writer),
                }
            }
            Self::ComponentChecksum(program_id, name) => {
                13u8.write_le(&mut writer)?;
                // Write the program ID.
                match program_id {
                    None => 0u8.write_le(&mut writer)?,
                    Some(program_id) => {
                        1u8.write_le(&mut writer)?;
                        program_id.write_le(&mut writer)?;
                    }
                }
                // Write the component name.
                name.write_le(&mut writer)
            }
        }
    }
}
