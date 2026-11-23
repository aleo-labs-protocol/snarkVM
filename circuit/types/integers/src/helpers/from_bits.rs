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

impl<E: Environment, I: IntegerType> FromBits for Integer<E, I> {
    type Boolean = Boolean<E>;

    /// Initializes a new integer from a list of little-endian bits *with* trailing zeros.
    fn from_bits_le(bits_le: &[Self::Boolean]) -> Self {
        // Note: `unwrap()` is safe as the integer is at most 128 bits.
        let i_bits = usize::try_from(I::BITS).unwrap();

        // Ensure the list of booleans is within the allowed size in bits.
        let num_bits = bits_le.len() as u64;
        if num_bits > I::BITS {
            // Check that all excess bits are zero.
            Boolean::assert_bits_are_zero(&bits_le[i_bits..])
        }

        // Construct the sanitized list of bits, resizing up if necessary.
        let mut bits_le = bits_le.iter().take(i_bits).cloned().collect::<Vec<_>>();
        bits_le.resize(i_bits, Boolean::constant(false));

        Self { bits_le, phantom: Default::default() }
    }

    /// Initializes a new integer from a list of big-endian bits *with* leading zeros.
    fn from_bits_be(bits_be: &[Self::Boolean]) -> Self {
        // Reverse the given bits from big-endian into little-endian.
        // Note: This is safe as the bit representation is consistent (there are leading zeros).
        let mut bits_le = bits_be.to_vec();
        bits_le.reverse();

        Self::from_bits_le(&bits_le)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_from_bits_le<I: IntegerType>(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random integer.
            let expected = Uniform::rand(&mut rng);
            let given_bits = Integer::<Circuit, I>::new(mode, expected).to_bits_le();
            let expected_size_in_bits = given_bits.len();

            Circuit::scope(format!("{mode} {i}"), || {
                let candidate = Integer::<Circuit, I>::from_bits_le(&given_bits);
                assert_eq!(expected, candidate.eject_value());
                assert_eq!(expected_size_in_bits, candidate.bits_le.len());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            // Add excess zero bits.
            // Note: `unwrap()` is safe as `i` is less than `ITERATIONS`.
            let num_excess_bits = usize::try_from(i).unwrap();
            let candidate = [given_bits, vec![Boolean::new(mode, false); num_excess_bits]].concat();

            Circuit::scope(format!("Excess {mode} {i}"), || {
                let candidate = Integer::<Circuit, I>::from_bits_le(&candidate);
                assert_eq!(expected, candidate.eject_value());
                assert_eq!(expected_size_in_bits, candidate.bits_le.len());
                match mode.is_constant() {
                    true => assert_scope!(num_constants, num_public, num_private, num_constraints),
                    // `num_constraints` is incremented by one for each excess bit.
                    false => {
                        assert_scope!(num_constants, num_public, num_private, if i == 0 { 0 } else { 1 })
                    }
                };
            });
        }
    }

    fn check_from_bits_be<I: IntegerType>(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random integer.
            let expected = Uniform::rand(&mut rng);
            let given_bits = Integer::<Circuit, I>::new(mode, expected).to_bits_be();
            let expected_size_in_bits = given_bits.len();

            Circuit::scope(format!("{mode} {i}"), || {
                let candidate = Integer::<Circuit, I>::from_bits_be(&given_bits);
                assert_eq!(expected, candidate.eject_value());
                assert_eq!(expected_size_in_bits, candidate.bits_le.len());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            // Add excess zero bits.
            // Note: `unwrap()` is safe as `i` is less than `ITERATIONS`.
            let num_excess_bits = usize::try_from(i).unwrap();
            let candidate = [vec![Boolean::new(mode, false); num_excess_bits], given_bits].concat();

            Circuit::scope(format!("Excess {mode} {i}"), || {
                let candidate = Integer::<Circuit, I>::from_bits_be(&candidate);
                assert_eq!(expected, candidate.eject_value());
                assert_eq!(expected_size_in_bits, candidate.bits_le.len());
                match mode.is_constant() {
                    true => assert_scope!(num_constants, num_public, num_private, num_constraints),
                    // `num_constraints` is incremented by one for each excess bit.
                    false => {
                        assert_scope!(num_constants, num_public, num_private, if i == 0 { 0 } else { 1 })
                    }
                };
            });
        }
    }

    // Tests for u8.

    #[test]
    fn test_u8_from_bits_le_constant() {
        type I = u8;
        check_from_bits_le::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_u8_from_bits_le_public() {
        type I = u8;
        check_from_bits_le::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_u8_from_bits_le_private() {
        type I = u8;
        check_from_bits_le::<I>(Mode::Private, 0, 0, 0, 0);
    }

    #[test]
    fn test_u8_from_bits_be_constant() {
        type I = u8;
        check_from_bits_be::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_u8_from_bits_be_public() {
        type I = u8;
        check_from_bits_be::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_u8_from_bits_be_private() {
        type I = u8;
        check_from_bits_be::<I>(Mode::Private, 0, 0, 0, 0);
    }

    // Tests for i8.

    #[test]
    fn test_i8_from_bits_le_constant() {
        type I = i8;
        check_from_bits_le::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_i8_from_bits_le_public() {
        type I = i8;
        check_from_bits_le::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_i8_from_bits_le_private() {
        type I = i8;
        check_from_bits_le::<I>(Mode::Private, 0, 0, 0, 0);
    }

    #[test]
    fn test_i8_from_bits_be_constant() {
        type I = i8;
        check_from_bits_be::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_i8_from_bits_be_public() {
        type I = i8;
        check_from_bits_be::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_i8_from_bits_be_private() {
        type I = i8;
        check_from_bits_be::<I>(Mode::Private, 0, 0, 0, 0);
    }

    // Tests for u16.

    #[test]
    fn test_u16_from_bits_le_constant() {
        type I = u16;
        check_from_bits_le::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_u16_from_bits_le_public() {
        type I = u16;
        check_from_bits_le::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_u16_from_bits_le_private() {
        type I = u16;
        check_from_bits_le::<I>(Mode::Private, 0, 0, 0, 0);
    }

    #[test]
    fn test_u16_from_bits_be_constant() {
        type I = u16;
        check_from_bits_be::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_u16_from_bits_be_public() {
        type I = u16;
        check_from_bits_be::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_u16_from_bits_be_private() {
        type I = u16;
        check_from_bits_be::<I>(Mode::Private, 0, 0, 0, 0);
    }

    // Tests for i16.

    #[test]
    fn test_i16_from_bits_le_constant() {
        type I = i16;
        check_from_bits_le::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_i16_from_bits_le_public() {
        type I = i16;
        check_from_bits_le::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_i16_from_bits_le_private() {
        type I = i16;
        check_from_bits_le::<I>(Mode::Private, 0, 0, 0, 0);
    }

    #[test]
    fn test_i16_from_bits_be_constant() {
        type I = i16;
        check_from_bits_be::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_i16_from_bits_be_public() {
        type I = i16;
        check_from_bits_be::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_i16_from_bits_be_private() {
        type I = i16;
        check_from_bits_be::<I>(Mode::Private, 0, 0, 0, 0);
    }

    // Tests for u32.

    #[test]
    fn test_u32_from_bits_le_constant() {
        type I = u32;
        check_from_bits_le::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_u32_from_bits_le_public() {
        type I = u32;
        check_from_bits_le::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_u32_from_bits_le_private() {
        type I = u32;
        check_from_bits_le::<I>(Mode::Private, 0, 0, 0, 0);
    }

    #[test]
    fn test_u32_from_bits_be_constant() {
        type I = u32;
        check_from_bits_be::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_u32_from_bits_be_public() {
        type I = u32;
        check_from_bits_be::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_u32_from_bits_be_private() {
        type I = u32;
        check_from_bits_be::<I>(Mode::Private, 0, 0, 0, 0);
    }

    // Tests for i32.

    #[test]
    fn test_i32_from_bits_le_constant() {
        type I = i32;
        check_from_bits_le::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_i32_from_bits_le_public() {
        type I = i32;
        check_from_bits_le::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_i32_from_bits_le_private() {
        type I = i32;
        check_from_bits_le::<I>(Mode::Private, 0, 0, 0, 0);
    }

    #[test]
    fn test_i32_from_bits_be_constant() {
        type I = i32;
        check_from_bits_be::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_i32_from_bits_be_public() {
        type I = i32;
        check_from_bits_be::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_i32_from_bits_be_private() {
        type I = i32;
        check_from_bits_be::<I>(Mode::Private, 0, 0, 0, 0);
    }

    // Tests for u64.

    #[test]
    fn test_u64_from_bits_le_constant() {
        type I = u64;
        check_from_bits_le::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_u64_from_bits_le_public() {
        type I = u64;
        check_from_bits_le::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_u64_from_bits_le_private() {
        type I = u64;
        check_from_bits_le::<I>(Mode::Private, 0, 0, 0, 0);
    }

    #[test]
    fn test_u64_from_bits_be_constant() {
        type I = u64;
        check_from_bits_be::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_u64_from_bits_be_public() {
        type I = u64;
        check_from_bits_be::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_u64_from_bits_be_private() {
        type I = u64;
        check_from_bits_be::<I>(Mode::Private, 0, 0, 0, 0);
    }

    // Tests for i64.

    #[test]
    fn test_i64_from_bits_le_constant() {
        type I = i64;
        check_from_bits_le::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_i64_from_bits_le_public() {
        type I = i64;
        check_from_bits_le::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_i64_from_bits_le_private() {
        type I = i64;
        check_from_bits_le::<I>(Mode::Private, 0, 0, 0, 0);
    }

    #[test]
    fn test_i64_from_bits_be_constant() {
        type I = i64;
        check_from_bits_be::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_i64_from_bits_be_public() {
        type I = i64;
        check_from_bits_be::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_i64_from_bits_be_private() {
        type I = i64;
        check_from_bits_be::<I>(Mode::Private, 0, 0, 0, 0);
    }

    // Tests for u128.

    #[test]
    fn test_u128_from_bits_le_constant() {
        type I = u128;
        check_from_bits_le::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_u128_from_bits_le_public() {
        type I = u128;
        check_from_bits_le::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_u128_from_bits_le_private() {
        type I = u128;
        check_from_bits_le::<I>(Mode::Private, 0, 0, 0, 0);
    }

    #[test]
    fn test_u128_from_bits_be_constant() {
        type I = u128;
        check_from_bits_be::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_u128_from_bits_be_public() {
        type I = u128;
        check_from_bits_be::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_u128_from_bits_be_private() {
        type I = u128;
        check_from_bits_be::<I>(Mode::Private, 0, 0, 0, 0);
    }

    // Tests for i128.

    #[test]
    fn test_i128_from_bits_le_constant() {
        type I = i128;
        check_from_bits_le::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_i128_from_bits_le_public() {
        type I = i128;
        check_from_bits_le::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_i128_from_bits_le_private() {
        type I = i128;
        check_from_bits_le::<I>(Mode::Private, 0, 0, 0, 0);
    }

    #[test]
    fn test_i128_from_bits_be_constant() {
        type I = i128;
        check_from_bits_be::<I>(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_i128_from_bits_be_public() {
        type I = i128;
        check_from_bits_be::<I>(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_i128_from_bits_be_private() {
        type I = i128;
        check_from_bits_be::<I>(Mode::Private, 0, 0, 0, 0);
    }
}
