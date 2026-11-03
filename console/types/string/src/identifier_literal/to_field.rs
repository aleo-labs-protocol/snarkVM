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

impl<E: Environment> ToField for IdentifierLiteral<E> {
    type Field = Field<E>;

    /// Returns the identifier literal as a field element.
    fn to_field(&self) -> Result<Self::Field> {
        Field::from_bits_le(&self.bytes.to_bits_le())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_to_field() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a random identifier literal.
            let expected = IdentifierLiteral::<CurrentEnvironment>::rand(&mut rng);

            // Convert to field.
            let candidate = expected.to_field()?;

            // Extract the bits from the field representation.
            let candidate_bits_le = candidate.to_bits_le();
            assert_eq!(Field::<CurrentEnvironment>::size_in_bits(), candidate_bits_le.len());

            // Ensure all identifier bits match with the expected result.
            let expected_bits = expected.to_bits_le();
            let size_in_bits = SIZE_IN_BITS;
            for (i, (expected_bit, candidate_bit)) in
                expected_bits.iter().zip(&candidate_bits_le[..size_in_bits]).enumerate()
            {
                assert_eq!(expected_bit, candidate_bit, "Mismatch at bit {i}");
            }

            // Ensure all remaining bits are 0.
            for candidate_bit in &candidate_bits_le[size_in_bits..] {
                assert!(!candidate_bit);
            }

            // Verify round-trip through from_field.
            let recovered = IdentifierLiteral::<CurrentEnvironment>::from_field(&candidate)?;
            assert_eq!(expected, recovered);
        }
        Ok(())
    }
}
