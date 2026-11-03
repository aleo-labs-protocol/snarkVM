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

impl<E: Environment> FromBytes for IdentifierLiteral<E> {
    /// Reads the identifier literal from a buffer.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the number of content bytes.
        let num_bytes = u8::read_le(&mut reader)? as usize;
        // Validate the length.
        if num_bytes == 0 || num_bytes > SIZE_IN_BYTES {
            return Err(error("Invalid identifier literal length"));
        }
        // Read directly into the byte array (remaining bytes stay zero).
        let mut bytes = [0u8; SIZE_IN_BYTES];
        reader.read_exact(&mut bytes[..num_bytes])?;
        // Validate and construct the identifier literal.
        Self::from_bytes_array(bytes).map_err(|e| error(e.to_string()))
    }
}

impl<E: Environment> ToBytes for IdentifierLiteral<E> {
    /// Writes the identifier literal to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the length.
        let length = self.length();
        length.write_le(&mut writer)?;
        // Write the content bytes.
        writer.write_all(&self.bytes[..length as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_bytes_roundtrip() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let expected = IdentifierLiteral::<CurrentEnvironment>::rand(&mut rng);
            let expected_bytes = expected.to_bytes_le()?;
            let recovered = IdentifierLiteral::read_le(&expected_bytes[..])?;
            assert_eq!(expected, recovered);
        }
        Ok(())
    }

    #[test]
    fn test_bytes_single_char() -> Result<()> {
        let expected = IdentifierLiteral::<CurrentEnvironment>::new("a")?;
        let expected_bytes = expected.to_bytes_le()?;
        let recovered = IdentifierLiteral::read_le(&expected_bytes[..])?;
        assert_eq!(expected, recovered);
        Ok(())
    }

    #[test]
    fn test_bytes_length_zero() {
        // A length prefix of 0 should be rejected.
        let bytes = [0u8];
        let result = IdentifierLiteral::<CurrentEnvironment>::read_le(&bytes[..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_bytes_length_exceeds_max() {
        // A length prefix exceeding SIZE_IN_BYTES should be rejected.
        let length = u8::try_from(SIZE_IN_BYTES).expect("SIZE_IN_BYTES fits in u8") + 1;
        let mut bytes = vec![length];
        bytes.resize(length as usize + 1, b'a');
        let result = IdentifierLiteral::<CurrentEnvironment>::read_le(&bytes[..]);
        assert!(result.is_err());
    }
}
