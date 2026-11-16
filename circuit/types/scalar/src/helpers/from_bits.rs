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

impl<E: Environment> FromBits for Scalar<E> {
    type Boolean = Boolean<E>;

    /// Initializes a new scalar field element from a list of **little-endian** bits.
    ///   - If `bits_le` is longer than `E::ScalarField::size_in_bits()`, the excess bits are enforced to be `0`s.
    ///   - If `bits_le` is shorter than `E::ScalarField::size_in_bits()`, it is padded with `0`s up to scalar field size.
    fn from_bits_le(bits_le: &[Self::Boolean]) -> Self {
        debug_assert!(console::Scalar::<E::Network>::size_in_bits() < console::Field::<E::Network>::size_in_bits());

        // Retrieve the data and scalar field size.
        let size_in_data_bits = console::Scalar::<E::Network>::size_in_data_bits();
        let size_in_bits = console::Scalar::<E::Network>::size_in_bits();

        // Ensure the list of booleans is within the allowed size in bits.
        let num_bits = bits_le.len();
        if num_bits > size_in_bits {
            // Check that all excess bits are zero.
            Boolean::assert_bits_are_zero(&bits_le[size_in_bits..]);
        }

        if num_bits > size_in_data_bits {
            // As `bits_le[size_in_bits..]` is guaranteed to be zero from the above logic,
            // and `bits_le` is greater than `size_in_data_bits`, it is safe to truncate `bits_le` to `size_in_bits`.
            let bits_le = &bits_le[..size_in_bits];

            // Reconstruct the bits as a linear combination representing the original scalar as a field.
            let mut accumulator = Field::zero();
            let mut coefficient = Field::one();
            for bit in bits_le {
                accumulator += Field::from_boolean(bit) * &coefficient;
                coefficient = coefficient.double();
            }

            // Construct the scalar.
            let cell = OnceCell::new();
            cell.set(bits_le.to_vec()).unwrap();
            let scalar = Scalar { field: accumulator, bits_le: cell };

            // Retrieve the modulus & subtract by 1 as we'll check `bits_le` is less than or *equal* to this value.
            // (For advanced users) ScalarField::MODULUS - 1 is equivalent to -1 in the field.
            let modulus_minus_one = -E::ScalarField::one();

            // Assert `bits_le <= (ScalarField::MODULUS - 1)`, which is equivalent to `bits_le < ScalarField::MODULUS`.
            Boolean::assert_less_than_or_equal_constant(bits_le, &modulus_minus_one.to_bits_le());

            // Return the scalar.
            scalar
        } else {
            // Construct the sanitized list of bits, resizing up if necessary.
            let mut bits_le = bits_le.iter().take(size_in_bits).cloned().collect::<Vec<_>>();
            bits_le.resize(size_in_bits, Boolean::constant(false));

            // Reconstruct the bits as a linear combination representing the original scalar as a field.
            let mut accumulator = Field::zero();
            let mut coefficient = Field::one();
            for bit in &bits_le {
                accumulator += Field::from_boolean(bit) * &coefficient;
                coefficient = coefficient.double();
            }

            // Return the scalar.
            let cell = OnceCell::new();
            cell.set(bits_le.to_vec()).unwrap();
            Scalar { field: accumulator, bits_le: cell }
        }
    }

    /// Initializes a new scalar field element from a list of big-endian bits *without* leading zeros.
    fn from_bits_be(bits_be: &[Self::Boolean]) -> Self {
        // Reverse the given bits from big-endian into little-endian.
        // Note: This is safe as the bit representation is consistent (there are no leading zeros).
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

    fn check_from_bits_le(mode: Mode, num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random element.
            let expected = Uniform::rand(&mut rng);
            let given_bits = Scalar::<Circuit>::new(mode, expected).to_bits_le();
            let expected_size_in_bits = given_bits.len();

            Circuit::scope(format!("{mode} {i}"), || {
                let candidate = Scalar::<Circuit>::from_bits_le(&given_bits);
                assert_eq!(expected, candidate.eject_value());
                assert_eq!(expected_size_in_bits, candidate.bits_le.get().unwrap().len());
                assert_eq!(expected_size_in_bits, candidate.to_bits_le().len());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            // Add excess zero bits.
            // Note: `unwrap()` is safe as `i` is less than `ITERATIONS`.
            let num_excess_bits = usize::try_from(i).unwrap();
            let candidate = [given_bits, vec![Boolean::new(mode, false); num_excess_bits]].concat();

            Circuit::scope(format!("Excess {mode} {i}"), || {
                let candidate = Scalar::<Circuit>::from_bits_le(&candidate);
                assert_eq!(expected, candidate.eject_value());
                assert_eq!(expected_size_in_bits, candidate.bits_le.get().unwrap().len());
                match mode.is_constant() {
                    true => assert_scope!(num_constants, num_public, num_private, num_constraints),
                    // `num_private` gets 1 free excess bit, then is incremented by one for each excess bit.
                    // `num_constraints` is incremented by one for each excess bit.
                    false => {
                        assert_scope!(
                            num_constants,
                            num_public,
                            num_private,
                            num_constraints + if i == 0 { 0 } else { 1 }
                        )
                    }
                };
            });
        }
    }

    fn check_from_bits_be(mode: Mode, num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random element.
            let expected = Uniform::rand(&mut rng);
            let given_bits = Scalar::<Circuit>::new(mode, expected).to_bits_be();
            let expected_size_in_bits = given_bits.len();

            Circuit::scope(format!("{mode} {i}"), || {
                let candidate = Scalar::<Circuit>::from_bits_be(&given_bits);
                assert_eq!(expected, candidate.eject_value());
                assert_eq!(expected_size_in_bits, candidate.bits_le.get().unwrap().len());
                assert_eq!(expected_size_in_bits, candidate.to_bits_be().len());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            // Add excess zero bits.
            // Note: `unwrap()` is safe as `i` is less than `ITERATIONS`.
            let num_excess_bits = usize::try_from(i).unwrap();
            let candidate = [vec![Boolean::new(mode, false); num_excess_bits], given_bits].concat();

            Circuit::scope(format!("Excess {mode} {i}"), || {
                let candidate = Scalar::<Circuit>::from_bits_be(&candidate);
                assert_eq!(expected, candidate.eject_value());
                assert_eq!(expected_size_in_bits, candidate.bits_le.get().unwrap().len());
                match mode.is_constant() {
                    true => assert_scope!(num_constants, num_public, num_private, num_constraints),
                    // `num_private` gets 1 free excess bit, then is incremented by one for each excess bit.
                    // `num_constraints` is incremented by one for each excess bit.
                    false => {
                        assert_scope!(
                            num_constants,
                            num_public,
                            num_private,
                            num_constraints + if i == 0 { 0 } else { 1 }
                        )
                    }
                };
            });
        }
    }

    #[test]
    fn test_from_bits_le_constant() {
        check_from_bits_le(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_from_bits_le_public() {
        check_from_bits_le(Mode::Public, 0, 0, 250, 251);
    }

    #[test]
    fn test_from_bits_le_private() {
        check_from_bits_le(Mode::Private, 0, 0, 250, 251);
    }

    #[test]
    fn test_from_bits_be_constant() {
        check_from_bits_be(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_from_bits_be_public() {
        check_from_bits_be(Mode::Public, 0, 0, 250, 251);
    }

    #[test]
    fn test_from_bits_be_private() {
        check_from_bits_be(Mode::Private, 0, 0, 250, 251);
    }
}
