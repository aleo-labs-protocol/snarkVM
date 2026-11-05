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

impl<E: Environment> FromBytes for Group<E> {
    /// Reads the group from a buffer.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        Self::from_x_coordinate(FromBytes::read_le(&mut reader)?).map_err(into_io_error)
    }
}

impl<E: Environment> ToBytes for Group<E> {
    /// Writes the group to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.to_x_coordinate().write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 10_000;

    #[test]
    fn test_bytes() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new group.
            let expected = Group::<CurrentEnvironment>::rand(&mut rng);

            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le()?;
            assert_eq!(expected, Group::read_le(&expected_bytes[..])?);
            assert_eq!(expected, Group::read_le_unchecked(&expected_bytes[..])?);
            assert!(Group::<CurrentEnvironment>::read_le(&expected_bytes[1..]).is_err());
            assert!(Group::<CurrentEnvironment>::read_le_unchecked(&expected_bytes[1..]).is_err());
        }
        Ok(())
    }
}
