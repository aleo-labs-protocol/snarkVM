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

impl<E: Environment> FromBits for IdentifierLiteral<E> {
    /// Initializes an identifier literal from a list of little-endian bits.
    fn from_bits_le(bits_le: &[bool]) -> Result<Self> {
        // Ensure there are enough bits.
        ensure!(bits_le.len() >= SIZE_IN_BITS, "Not enough bits for identifier literal");

        // If there are excess bits, ensure they are all zero.
        if bits_le.len() > SIZE_IN_BITS {
            let has_nonzero = bits_le[SIZE_IN_BITS..].iter().any(|&b| b);
            ensure!(!has_nonzero, "Excess bits are not zero");
        }

        // Reconstruct bytes from the first SIZE_IN_BITS bits directly into a fixed-size array.
        let mut bytes = [0u8; SIZE_IN_BYTES];
        for (i, chunk) in bits_le[..SIZE_IN_BITS].chunks(8).enumerate() {
            bytes[i] = u8::from_bits_le(chunk)?;
        }

        // Validate and construct the identifier literal.
        Self::from_bytes_array(bytes)
    }

    /// Initializes an identifier literal from a list of big-endian bits.
    fn from_bits_be(bits_be: &[bool]) -> Result<Self> {
        // Reverse the bits to get little-endian order.
        let bits_le: Vec<bool> = bits_be.iter().rev().copied().collect();
        Self::from_bits_le(&bits_le)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_from_bits_le_roundtrip() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let original = IdentifierLiteral::<CurrentEnvironment>::rand(&mut rng);
            let bits = original.to_bits_le();
            let recovered = IdentifierLiteral::<CurrentEnvironment>::from_bits_le(&bits)?;
            assert_eq!(original, recovered);
        }
        Ok(())
    }

    #[test]
    fn test_from_bits_be_roundtrip() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let original = IdentifierLiteral::<CurrentEnvironment>::rand(&mut rng);
            let bits = original.to_bits_be();
            let recovered = IdentifierLiteral::<CurrentEnvironment>::from_bits_be(&bits)?;
            assert_eq!(original, recovered);
        }
        Ok(())
    }
}
