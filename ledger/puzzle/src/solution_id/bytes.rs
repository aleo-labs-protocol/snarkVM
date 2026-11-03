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

impl<N: Network> FromBytes for SolutionID<N> {
    /// Reads the solution ID from the buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let nonce = u64::read_le(&mut reader)?;

        Ok(Self::from(nonce))
    }
}

impl<N: Network> ToBytes for SolutionID<N> {
    /// Writes the solution ID to the buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.0.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_bytes() -> Result<()> {
        let mut rng = TestRng::default();
        // Sample a new solution ID.
        let expected = SolutionID::<CurrentNetwork>::from(rng.random::<u64>());

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le()?;
        assert_eq!(expected_bytes.len(), 8);
        assert_eq!(expected, SolutionID::read_le(&expected_bytes[..])?);
        assert!(SolutionID::<CurrentNetwork>::read_le(&expected_bytes[1..]).is_err());

        Ok(())
    }
}
