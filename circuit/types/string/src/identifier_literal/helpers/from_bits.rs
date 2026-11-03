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
    type Boolean = Boolean<E>;

    /// Creates an identifier literal from a list of little-endian bits.
    ///
    /// - If more than SIZE_IN_BITS bits are provided, upper bits are asserted to be zero.
    /// - If fewer than SIZE_IN_BITS bits are provided, the input is zero-padded.
    /// - Validates the identifier format (character set, first char is a letter, trailing nulls).
    fn from_bits_le(bits_le: &[Self::Boolean]) -> Self {
        // If there are more bits than needed, assert upper bits are zero.
        if bits_le.len() > SIZE_IN_BITS {
            Boolean::assert_bits_are_zero(&bits_le[SIZE_IN_BITS..]);
        }

        // Resize to exactly SIZE_IN_BITS: truncates if longer, zero-pads if shorter.
        let mut padded = bits_le.to_vec();
        padded.resize(SIZE_IN_BITS, Boolean::constant(false));

        // Convert bits to bytes using chunks.
        let mut bytes_vec = Vec::with_capacity(SIZE_IN_BYTES);
        for chunk in padded.chunks(8) {
            bytes_vec.push(U8::from_bits_le(chunk));
        }
        // Note. This unwrap is safe since the length of `bytes_vec` matches SIZE_IN_BYTES.
        let bytes: [U8<E>; SIZE_IN_BYTES] =
            bytes_vec.try_into().unwrap_or_else(|_| E::halt("Failed to convert to byte array"));

        // Validate and construct using the shared helper.
        Self::from_bytes(bytes)
    }

    /// Creates an identifier literal from a list of big-endian bits.
    fn from_bits_be(bits_be: &[Self::Boolean]) -> Self {
        // Reverse the bits to get little-endian order.
        let bits_le: Vec<_> = bits_be.iter().rev().cloned().collect();
        Self::from_bits_le(&bits_le)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::{Circuit, assert_scope_fails};
    use snarkvm_utilities::{TestRng, Uniform};

    type CurrentEnvironment = Circuit;

    const ITERATIONS: usize = 10;

    fn check_from_bits_le(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Construct a random console identifier literal.
            let expected = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);

            // Get the bits from a circuit representation.
            let injected = IdentifierLiteral::<CurrentEnvironment>::new(mode, expected);
            let bits = injected.to_bits_le();

            Circuit::scope(format!("from_bits_le {mode}"), || {
                // Reconstruct from bits.
                let candidate = IdentifierLiteral::<CurrentEnvironment>::from_bits_le(&bits);

                // Verify the value matches.
                assert_eq!(expected, candidate.eject_value());
                assert_eq!(mode, candidate.eject_mode());

                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            Circuit::reset();
        }
        Ok(())
    }

    fn check_from_bits_be(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Construct a random console identifier literal.
            let expected = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);

            // Get the bits from a circuit representation.
            let injected = IdentifierLiteral::<CurrentEnvironment>::new(mode, expected);
            let bits = injected.to_bits_be();

            Circuit::scope(format!("from_bits_be {mode}"), || {
                // Reconstruct from bits.
                let candidate = IdentifierLiteral::<CurrentEnvironment>::from_bits_be(&bits);

                // Verify the value matches.
                assert_eq!(expected, candidate.eject_value());
                assert_eq!(mode, candidate.eject_mode());

                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            Circuit::reset();
        }
        Ok(())
    }

    #[test]
    fn test_from_bits_le_constant() -> Result<()> {
        check_from_bits_le(Mode::Constant, 31, 0, 0, 0)
    }

    #[test]
    fn test_from_bits_le_public() -> Result<()> {
        check_from_bits_le(Mode::Public, 0, 0, 375, 561)
    }

    #[test]
    fn test_from_bits_le_private() -> Result<()> {
        check_from_bits_le(Mode::Private, 0, 0, 375, 561)
    }

    #[test]
    fn test_from_bits_be_constant() -> Result<()> {
        check_from_bits_be(Mode::Constant, 31, 0, 0, 0)
    }

    #[test]
    fn test_from_bits_be_public() -> Result<()> {
        check_from_bits_be(Mode::Public, 0, 0, 375, 561)
    }

    #[test]
    fn test_from_bits_be_private() -> Result<()> {
        check_from_bits_be(Mode::Private, 0, 0, 375, 561)
    }

    #[test]
    fn test_from_bits_le_with_excess_zero_bits() -> Result<()> {
        // Test that excess zero bits are accepted.
        let expected =
            console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::new("hello").unwrap();

        // Get the bits and add excess zeros.
        let injected = IdentifierLiteral::<CurrentEnvironment>::new(Mode::Private, expected);
        let mut bits = injected.to_bits_le();
        // Add 5 extra zero bits (simulate field bits > 248).
        for _ in 0..5 {
            bits.push(Boolean::new(Mode::Private, false));
        }

        Circuit::scope("from_bits_le with excess", || {
            let candidate = IdentifierLiteral::<CurrentEnvironment>::from_bits_le(&bits);
            assert_eq!(expected, candidate.eject_value());
            assert!(Circuit::is_satisfied());
            assert_scope!(0, 0, 375, 562);
        });

        Circuit::reset();
        Ok(())
    }

    #[test]
    fn test_from_bits_le_with_excess_one_bits_unsatisfied() {
        // Test that excess non-zero bits cause unsatisfied circuit.
        let expected =
            console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::new("hello").unwrap();

        // Get the bits and add excess one.
        let injected = IdentifierLiteral::<CurrentEnvironment>::new(Mode::Private, expected);
        let mut bits = injected.to_bits_le();
        // Add an extra one bit.
        bits.push(Boolean::new(Mode::Private, true));

        Circuit::scope("from_bits_le with excess one", || {
            let _candidate = IdentifierLiteral::<CurrentEnvironment>::from_bits_le(&bits);
            assert_scope_fails!(0, 0, 375, 562);
        });

        // Circuit should be unsatisfied.
        assert!(!Circuit::is_satisfied());
        Circuit::reset();
    }
}
