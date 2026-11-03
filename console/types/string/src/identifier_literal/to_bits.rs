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

impl<E: Environment> ToBits for IdentifierLiteral<E> {
    /// Returns the little-endian bits of the identifier literal.
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        self.bytes.write_bits_le(vec);
    }

    /// Returns the big-endian bits of the identifier literal.
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        let initial_len = vec.len();
        self.write_bits_le(vec);
        vec[initial_len..].reverse();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_to_bits_length() {
        let literal = IdentifierLiteral::<CurrentEnvironment>::new("hello").unwrap();
        let bits = literal.to_bits_le();
        assert_eq!(bits.len(), SIZE_IN_BITS);
    }

    #[test]
    fn test_to_bits_le_roundtrip() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let literal = IdentifierLiteral::<CurrentEnvironment>::rand(&mut rng);
            let bits_le = literal.to_bits_le();
            // The field should be recoverable from the bits.
            let recovered_field = Field::<CurrentEnvironment>::from_bits_le(&bits_le).unwrap();
            assert_eq!(literal.to_field().unwrap(), recovered_field);
        }
    }

    #[test]
    fn test_to_bits_be_roundtrip() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let literal = IdentifierLiteral::<CurrentEnvironment>::rand(&mut rng);
            let bits_be = literal.to_bits_be();
            // Reverse to get LE and reconstruct.
            let bits_le: Vec<bool> = bits_be.iter().rev().copied().collect();
            let recovered_field = Field::<CurrentEnvironment>::from_bits_le(&bits_le).unwrap();
            assert_eq!(literal.to_field().unwrap(), recovered_field);
        }
    }
}
