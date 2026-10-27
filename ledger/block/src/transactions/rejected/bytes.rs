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

impl<N: Network> FromBytes for Rejected<N> {
    /// Reads the rejected transaction from a buffer, either with or without checking the data.
    fn read_le_with_unchecked<R: Read>(mut reader: R, unchecked: bool) -> IoResult<Self> {
        let variant = u8::read_le(&mut reader)?;
        match variant {
            0 => {
                // Read the program owner.
                let program_owner = ProgramOwner::read_le(&mut reader)?;
                // Read the deployment.
                let deployment = Deployment::read_le_with_unchecked(&mut reader, unchecked)?;
                // Return the rejected deployment.
                Ok(Self::new_deployment(program_owner, deployment))
            }
            1 => {
                // Read the execution.
                let execution = Execution::read_le_with_unchecked(&mut reader, unchecked)?;
                // Return the rejected execution.
                Ok(Self::new_execution(execution))
            }
            2.. => Err(error(format!("Failed to decode rejected transaction variant {variant}"))),
        }
    }

    /// Reads the rejected transaction from a buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, false)
    }

    /// Reads the rejected transaction from a buffer without checking the data.
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, true)
    }
}

impl<N: Network> ToBytes for Rejected<N> {
    /// Writes the rejected transaction to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Deployment(program_owner, deployment) => {
                // Write the variant.
                0u8.write_le(&mut writer)?;
                // Write the program owner.
                program_owner.write_le(&mut writer)?;
                // Write the deployment.
                deployment.write_le(&mut writer)
            }
            Self::Execution(execution) => {
                // Write the variant.
                1u8.write_le(&mut writer)?;
                // Write the execution.
                execution.write_le(&mut writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() {
        for expected in crate::transactions::rejected::test_helpers::sample_rejected_transactions() {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, Rejected::read_le(&expected_bytes[..]).unwrap());
            assert_eq!(expected, Rejected::read_le_unchecked(&expected_bytes[..]).unwrap());
        }
    }
}
