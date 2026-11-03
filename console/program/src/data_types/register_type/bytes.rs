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

impl<N: Network> ToBytes for RegisterType<N> {
    /// Writes the register type to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        u8::try_from(self.enum_index()).map_err(error)?.write_le(&mut writer)?;
        match self {
            Self::Plaintext(plaintext_type) => plaintext_type.write_le(&mut writer),
            Self::Record(identifier) => identifier.write_le(&mut writer),
            Self::ExternalRecord(locator) => locator.write_le(&mut writer),
            Self::Future(locator) => locator.write_le(&mut writer),
            Self::DynamicRecord => Ok(()), // No additional data to write.
            Self::DynamicFuture => Ok(()), // No additional data to write.
        }
    }
}

impl<N: Network> FromBytes for RegisterType<N> {
    /// Reads the register type from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let variant = u8::read_le(&mut reader)?;
        match variant {
            0 => Ok(Self::Plaintext(PlaintextType::read_le(&mut reader)?)),
            1 => Ok(Self::Record(Identifier::read_le(&mut reader)?)),
            2 => Ok(Self::ExternalRecord(Locator::read_le(&mut reader)?)),
            3 => Ok(Self::Future(Locator::read_le(&mut reader)?)),
            4 => Ok(Self::DynamicRecord),
            5 => Ok(Self::DynamicFuture),
            6.. => Err(error(format!("Failed to deserialize register type variant {variant}"))),
        }
    }
}
