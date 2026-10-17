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

impl<E: Environment> ToBits for Field<E> {
    type Boolean = Boolean<E>;

    /// Outputs the little-endian bit representation of `self` *without* trailing zeros.
    fn write_bits_le(&self, vec: &mut Vec<Self::Boolean>) {
        (&self).write_bits_le(vec);
    }

    /// Outputs the big-endian bit representation of `self` *without* leading zeros.
    fn write_bits_be(&self, vec: &mut Vec<Self::Boolean>) {
        (&self).write_bits_be(vec);
    }
}

impl<E: Environment> ToBits for &Field<E> {
    type Boolean = Boolean<E>;

    /// Outputs the unique, minimal little-endian bit representation of `self` *without* trailing zeros.
    fn write_bits_le(&self, vec: &mut Vec<Self::Boolean>) {
        // Compute the bits of the field value.
        let bits = self.bits_le.get_or_init(|| {
            // Extract a non-unique little-endian bit representation of `self`.
            let bits_le = self.to_non_unique_bits_le();

            // Ensure the bit representation is unique.
            {
                // Retrieve the modulus & subtract by 1 as we'll check `bits_le` is less than or *equal* to this value.
                // (For advanced users) BaseField::MODULUS - 1 is equivalent to -1 in the field.
                let modulus_minus_one = -E::BaseField::one();
                // Assert `bits_le <= (BaseField::MODULUS - 1)`, which is equivalent to `bits_le < BaseField::MODULUS`.
                Boolean::assert_less_than_or_equal_constant(&bits_le, &modulus_minus_one.to_bits_le())
            }

            bits_le
        });
        // Extend the vector with the bits of the field value.
        vec.extend_from_slice(bits)
    }

    /// Outputs the unique, minimal big-endian bit representation of `self` *without* leading zeros.
    fn write_bits_be(&self, vec: &mut Vec<Self::Boolean>) {
        let initial_len = vec.len();
        self.write_bits_le(vec);
        vec[initial_len..].reverse();
    }
}

impl<E: Environment> Field<E> {
    /// Outputs a non-unique little-endian bit representation of `self` *without* trailing zeros.
    ///
    /// The bits are only constrained to reconstruct `self` modulo the modulus, so a
    /// prover may assign the bits of `self + modulus` when they fit in `n` bits.
    /// This is safe in the only caller, `to_bits_le`, which immediately asserts
    /// that the bits are at most `modulus - 1`, restoring uniqueness.
    #[doc(hidden)]
    fn to_non_unique_bits_le(&self) -> Vec<Boolean<E>> {
        // Construct a vector of `Boolean`s comprising the bits of the field value.
        let bits_le = witness!(|self| self.to_bits_le());

        // Reconstruct the bits as a linear combination representing the original field value.
        let mut accumulator = Field::zero();
        let mut coefficient = Field::one();
        for bit in &bits_le {
            accumulator += Field::from_boolean(bit) * &coefficient;
            coefficient = coefficient.double();
        }

        // Ensure value * 1 == (2^i * b_i + ... + 2^0 * b_0)
        E::assert_eq(self, accumulator).expect("Field to_bits constraint unsatisfied");

        bits_le
    }
}

impl<E: Environment> Metrics<dyn ToBits<Boolean = Boolean<E>>> for Field<E> {
    type Case = Mode;

    fn count(case: &Self::Case) -> Count {
        match case {
            Mode::Constant => Count::is(253, 0, 0, 0),
            _ => Count::is(0, 0, 505, 507),
        }
    }
}

impl<E: Environment> OutputMode<dyn ToBits<Boolean = Boolean<E>>> for Field<E> {
    type Case = Mode;

    fn output_mode(case: &Self::Case) -> Mode {
        match case {
            Mode::Constant => Mode::Constant,
            _ => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_to_bits_le(mode: Mode) {
        let expected_number_of_bits = console::Field::<<Circuit as Environment>::Network>::size_in_bits();

        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random element.
            let expected = Uniform::rand(&mut rng);
            let candidate = Field::<Circuit>::new(mode, expected);

            Circuit::scope(format!("{mode} {i}"), || {
                let candidate_bits = candidate.to_bits_le();
                assert_eq!(expected_number_of_bits, candidate_bits.len());
                for (expected_bit, candidate_bit) in expected.to_bits_le().iter().zip_eq(&candidate_bits) {
                    assert_eq!(*expected_bit, candidate_bit.eject_value());
                }
                assert_count!(ToBits<Boolean>() => Field, &mode);
                assert_output_mode!(ToBits<Boolean>() => Field, &mode, candidate_bits);

                // Ensure a second call to `to_bits_le` does not incur additional costs.
                let candidate_bits = candidate.to_bits_le();
                assert_eq!(expected_number_of_bits, candidate_bits.len());
                assert_count!(ToBits<Boolean>() => Field, &mode);
                assert_output_mode!(ToBits<Boolean>() => Field, &mode, candidate_bits);
            });
        }
    }

    fn check_to_bits_be(mode: Mode) {
        let expected_number_of_bits = console::Field::<<Circuit as Environment>::Network>::size_in_bits();

        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random element.
            let expected = Uniform::rand(&mut rng);
            let candidate = Field::<Circuit>::new(mode, expected);

            Circuit::scope(format!("{mode} {i}"), || {
                let candidate_bits = candidate.to_bits_be();
                assert_eq!(expected_number_of_bits, candidate_bits.len());
                for (expected_bit, candidate_bit) in expected.to_bits_be().iter().zip_eq(&candidate_bits) {
                    assert_eq!(*expected_bit, candidate_bit.eject_value());
                }
                assert_count!(ToBits<Boolean>() => Field, &mode);
                assert_output_mode!(ToBits<Boolean>() => Field, &mode, candidate_bits);

                // Ensure a second call to `to_bits_be` does not incur additional costs.
                let candidate_bits = candidate.to_bits_be();
                assert_eq!(expected_number_of_bits, candidate_bits.len());
                assert_count!(ToBits<Boolean>() => Field, &mode);
                assert_output_mode!(ToBits<Boolean>() => Field, &mode, candidate_bits);
            });
        }
    }

    #[test]
    fn test_to_bits_le_constant() {
        check_to_bits_le(Mode::Constant);
    }

    #[test]
    fn test_to_bits_le_public() {
        check_to_bits_le(Mode::Public);
    }

    #[test]
    fn test_to_bits_le_private() {
        check_to_bits_le(Mode::Private);
    }

    #[test]
    fn test_to_bits_be_constant() {
        check_to_bits_be(Mode::Constant);
    }

    #[test]
    fn test_to_bits_be_public() {
        check_to_bits_be(Mode::Public);
    }

    #[test]
    fn test_to_bits_be_private() {
        check_to_bits_be(Mode::Private);
    }

    #[test]
    fn test_one() {
        /// Checks that the field element, when converted to little-endian bits, is well-formed.
        fn check_bits_le(candidate: Field<Circuit>) {
            for (i, bit) in candidate.to_bits_le().iter().enumerate() {
                match i == 0 {
                    true => assert!(bit.eject_value()),
                    false => assert!(!bit.eject_value()),
                }
            }
        }

        /// Checks that the field element, when converted to big-endian bits, is well-formed.
        fn check_bits_be(candidate: Field<Circuit>) {
            for (i, bit) in candidate.to_bits_be().iter().rev().enumerate() {
                match i == 0 {
                    true => assert!(bit.eject_value()),
                    false => assert!(!bit.eject_value()),
                }
            }
        }

        let one = console::Field::<<Circuit as Environment>::Network>::one();

        // Constant
        check_bits_le(Field::<Circuit>::new(Mode::Constant, one));
        check_bits_be(Field::<Circuit>::new(Mode::Constant, one));
        // Public
        check_bits_le(Field::<Circuit>::new(Mode::Public, one));
        check_bits_be(Field::<Circuit>::new(Mode::Public, one));
        // Private
        check_bits_le(Field::<Circuit>::new(Mode::Private, one));
        check_bits_be(Field::<Circuit>::new(Mode::Private, one));
    }
}
