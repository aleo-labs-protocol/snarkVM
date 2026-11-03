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

impl<N: Network> FromBytes for DynamicFuture<N> {
    /// Reads in a dynamic future from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Validate the version.
        if version != 1 {
            return Err(error(format!("Invalid dynamic future version: {version}")));
        }
        // Read the program name.
        let program_name = Field::read_le(&mut reader)?;
        // Read the program network.
        let program_network = Field::read_le(&mut reader)?;
        // Read the function name.
        let function_name = Field::read_le(&mut reader)?;
        // Read the argument checksum.
        let checksum = Field::read_le(&mut reader)?;
        // Return the dynamic future.
        Ok(Self::new_unchecked(program_name, program_network, function_name, checksum, None))
    }
}

impl<N: Network> ToBytes for DynamicFuture<N> {
    /// Writes a dynamic future to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;
        // Write the program name.
        self.program_name.write_le(&mut writer)?;
        // Write the program network.
        self.program_network.write_le(&mut writer)?;
        // Write the function name.
        self.function_name.write_le(&mut writer)?;
        // Write the argument checksum.
        self.checksum.write_le(&mut writer)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Argument, Future, Plaintext};
    use snarkvm_console_network::MainnetV0;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_bytes() {
        // Create a static future.
        let future = Future::<CurrentNetwork>::new(
            crate::ProgramID::from_str("test.aleo").unwrap(),
            crate::Identifier::from_str("foo").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())],
        );

        // Convert to dynamic future.
        let expected = DynamicFuture::from_future(&future).unwrap();

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        let candidate = DynamicFuture::<CurrentNetwork>::read_le(&expected_bytes[..]).unwrap();

        // Verify the fields match.
        assert_eq!(expected.program_name(), candidate.program_name());
        assert_eq!(expected.program_network(), candidate.program_network());
        assert_eq!(expected.function_name(), candidate.function_name());
        assert_eq!(expected.checksum(), candidate.checksum());
    }

    #[test]
    fn test_bytes_no_arguments() {
        // Create a static future with no arguments.
        let future = Future::<CurrentNetwork>::new(
            crate::ProgramID::from_str("credits.aleo").unwrap(),
            crate::Identifier::from_str("transfer").unwrap(),
            vec![],
        );

        // Convert to dynamic future.
        let expected = DynamicFuture::from_future(&future).unwrap();

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        let candidate = DynamicFuture::<CurrentNetwork>::read_le(&expected_bytes[..]).unwrap();

        // Verify the fields match.
        assert_eq!(expected.program_name(), candidate.program_name());
        assert_eq!(expected.program_network(), candidate.program_network());
        assert_eq!(expected.function_name(), candidate.function_name());
        assert_eq!(expected.checksum(), candidate.checksum());
    }

    #[test]
    fn test_bytes_multiple_arguments() {
        // Create a static future with multiple arguments.
        let future = Future::<CurrentNetwork>::new(
            crate::ProgramID::from_str("test.aleo").unwrap(),
            crate::Identifier::from_str("bar").unwrap(),
            vec![
                Argument::Plaintext(Plaintext::from_str("100u64").unwrap()),
                Argument::Plaintext(Plaintext::from_str("200u64").unwrap()),
                Argument::Plaintext(Plaintext::from_str("true").unwrap()),
            ],
        );

        // Convert to dynamic future.
        let expected = DynamicFuture::from_future(&future).unwrap();

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        let candidate = DynamicFuture::<CurrentNetwork>::read_le(&expected_bytes[..]).unwrap();

        // Verify the fields match.
        assert_eq!(expected.program_name(), candidate.program_name());
        assert_eq!(expected.program_network(), candidate.program_network());
        assert_eq!(expected.function_name(), candidate.function_name());
        assert_eq!(expected.checksum(), candidate.checksum());
    }
}
