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
    type Boolean = Boolean<E>;

    /// Returns the little-endian bits of the identifier literal.
    fn write_bits_le(&self, vec: &mut Vec<Boolean<E>>) {
        for byte in self.bytes.iter() {
            byte.write_bits_le(vec);
        }
    }

    /// Returns the big-endian bits of the identifier literal.
    fn write_bits_be(&self, vec: &mut Vec<Boolean<E>>) {
        // Write in LE order, then reverse the appended bits.
        let initial_len = vec.len();
        self.write_bits_le(vec);
        vec[initial_len..].reverse();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    type CurrentEnvironment = Circuit;

    const ITERATIONS: usize = 10;

    fn check_to_bits_le(mode: Mode) -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Construct a random console identifier literal.
            let expected = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);

            // Inject into the circuit (outside the scope).
            let candidate = IdentifierLiteral::<CurrentEnvironment>::new(mode, expected);

            Circuit::scope(format!("to_bits_le {mode}"), || {
                // Get circuit bits and eject their values.
                let candidate_bits = candidate.to_bits_le();

                // Verify the correct number of bits.
                assert_eq!(candidate_bits.len(), IdentifierLiteral::<CurrentEnvironment>::size_in_bits());

                // Verify each ejected bit matches the expected byte-level bit decomposition.
                let expected_bits = expected.to_bits_le();
                for (expected_bit, candidate_bit) in expected_bits.iter().zip(candidate_bits.iter()) {
                    assert_eq!(*expected_bit, candidate_bit.eject_value());
                }

                assert_scope!(0, 0, 0, 0);
            });

            Circuit::reset();
        }
        Ok(())
    }

    fn check_to_bits_be(mode: Mode) -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Construct a random console identifier literal.
            let expected = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);

            // Inject into the circuit (outside the scope).
            let candidate = IdentifierLiteral::<CurrentEnvironment>::new(mode, expected);

            Circuit::scope(format!("to_bits_be {mode}"), || {
                // Get circuit bits and eject their values.
                let candidate_bits = candidate.to_bits_be();

                // Verify the correct number of bits.
                assert_eq!(candidate_bits.len(), IdentifierLiteral::<CurrentEnvironment>::size_in_bits());

                // Verify each ejected bit matches the expected byte-level bit decomposition.
                let expected_bits = expected.to_bits_be();
                for (expected_bit, candidate_bit) in expected_bits.iter().zip(candidate_bits.iter()) {
                    assert_eq!(*expected_bit, candidate_bit.eject_value());
                }

                assert_scope!(0, 0, 0, 0);
            });

            Circuit::reset();
        }
        Ok(())
    }

    #[test]
    fn test_to_bits_le_constant() -> Result<()> {
        check_to_bits_le(Mode::Constant)
    }

    #[test]
    fn test_to_bits_le_public() -> Result<()> {
        check_to_bits_le(Mode::Public)
    }

    #[test]
    fn test_to_bits_le_private() -> Result<()> {
        check_to_bits_le(Mode::Private)
    }

    #[test]
    fn test_to_bits_be_constant() -> Result<()> {
        check_to_bits_be(Mode::Constant)
    }

    #[test]
    fn test_to_bits_be_public() -> Result<()> {
        check_to_bits_be(Mode::Public)
    }

    #[test]
    fn test_to_bits_be_private() -> Result<()> {
        check_to_bits_be(Mode::Private)
    }
}
