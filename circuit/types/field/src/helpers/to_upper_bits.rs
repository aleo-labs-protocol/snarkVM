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

impl<E: Environment> ToUpperBits for Field<E> {
    type Boolean = Boolean<E>;

    ///
    /// Outputs the upper `k` bits of an `n`-bit field element in little-endian representation.
    /// Enforces that the lower `n - k` bits are zero.
    ///
    /// Also enforces that the shifted value is less than the modulus, by asserting
    /// that the bits are at most the upper `k` bits of `modulus - 1`. Without this
    /// assertion, a prover could assign the bits of `value + modulus`, shifted by
    /// `2^(n - k)`, which reconstructs `value` modulo the modulus.
    ///
    fn to_upper_bits_le(&self, k: usize) -> Vec<Self::Boolean> {
        let mut bits_le = self.to_upper_bits_be(k);
        bits_le.reverse();
        bits_le
    }

    ///
    /// Outputs the upper `k` bits of an `n`-bit field element in big-endian representation.
    /// Enforces that the lower `n - k` bits are zero.
    ///
    /// Also enforces that the shifted value is less than the modulus, as this returns
    /// the little-endian decomposition in reverse order.
    ///
    fn to_upper_bits_be(&self, k: usize) -> Vec<Self::Boolean> {
        // Ensure the size is within the allowed capacity.
        if k > E::BaseField::size_in_bits() {
            E::halt(format!(
                "Attempted to extract {k} bits from a {}-bit base field element",
                E::BaseField::size_in_bits()
            ))
        }

        // Construct a vector of `Boolean`s comprising the bits of the field value.
        let bits: Vec<Boolean<E>> = witness!(|self| self.to_bits_be().into_iter().take(k).collect());

        // Reconstruct the bits as a linear combination representing the original field value.
        let mut accumulator = Field::zero();
        let mut coefficient = Field::one();
        for _ in 0..(E::BaseField::size_in_bits() - k) {
            coefficient = coefficient.double();
        }
        for bit in bits.iter().rev() {
            accumulator += Field::from_boolean(bit) * &coefficient;
            coefficient = coefficient.double();
        }

        // Ensure value * 1 == (2^n * b_n + ... + 2^{n-k} * b_{n-k})
        // and ensures that b_{n-k-1}, ..., b_0 are all equal to zero.
        E::assert_eq(self, accumulator).expect("Field to_upper_bits constraint unsatisfied");

        // Ensure the bits encode an integer less than the modulus. As the lower `n - k` bits are zero,
        // this holds if and only if the upper `k` bits are at most the upper `k` bits of `modulus - 1`.
        let bits_le = bits.iter().rev().cloned().collect::<Vec<_>>();
        let modulus_minus_one = -E::BaseField::one();
        Boolean::assert_less_than_or_equal_constant(
            &bits_le,
            &modulus_minus_one.to_bits_le()[E::BaseField::size_in_bits() - k..],
        );

        bits
    }
}

impl<E: Environment> Metrics<dyn ToUpperBits<Boolean = Boolean<E>>> for Field<E> {
    type Case = (Mode, u64);

    fn count(case: &Self::Case) -> Count {
        match case {
            (Mode::Constant, k) => Count::is(*k, 0, 0, 0),
            (_, k) => {
                // The range check is free up to and including the first zero bit of its constant. Each later bit
                // costs one private variable and one constraint, and the final assertion costs one constraint.
                let size_in_bits = E::BaseField::size_in_bits();
                let constant_bits_le = &(-E::BaseField::one()).to_bits_le()[size_in_bits - *k as usize..];
                let (num_private, num_constraints) = match constant_bits_le.iter().position(|bit| !bit) {
                    Some(index) => (k - 1 - index as u64, k - index as u64),
                    None => (0, 0),
                };
                Count::is(0, 0, k + num_private, k + 1 + num_constraints)
            }
        }
    }
}

impl<E: Environment> OutputMode<dyn ToUpperBits<Boolean = Boolean<E>>> for Field<E> {
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

    #[rustfmt::skip]
    fn check_to_upper_k_bits_be<I: IntegerType + Unsigned>(
        mode: Mode,
    ) {
        let size_in_bits = console::Field::<<Circuit as Environment>::Network>::size_in_bits();
        let size_in_bytes = size_in_bits.div_ceil(8);
        let num_leading_zero_bits = (size_in_bytes * 8) - size_in_bits;

        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random unsigned integer.
            let value: I = Uniform::rand(&mut rng);
            let expected = value.to_bits_be();

            // Construct the unsigned integer as a field element.
            let candidate = {
                //
                // Restructure the value as field element as follows.
                //
                // MSB | MSB-1 | MSB-2 | MSB-3 | MSB-4 | ... | MSB-k | MSB-k-1 | ... | LSB
                // ------------------------------------------------------------------------
                //  0  |   0   |   0   |   0   |  b_k  | ... |  b_0  |    0    | ... |  0
                //
                // For advanced readers: We extend the leading zeros one-past `MODULUS_BITS`
                // to ensure `CAPACITY` is always satisfied for testing.
                //
                let bits_be = {
                    let mut bits_be_with_leading_zeros = vec![false; num_leading_zero_bits + 1];
                    for bit in value.to_bits_be().into_iter() {
                        bits_be_with_leading_zeros.push(bit);
                    }
                    bits_be_with_leading_zeros.resize(size_in_bytes * 8, false); // Pad up to field byte-aligned size.
                    bits_be_with_leading_zeros
                };
                Field::<Circuit>::new(mode, console::Field::from_bits_be(&bits_be).unwrap())
            };

            Circuit::scope(format!("{mode} {i}"), || {
                let num_bits_with_capacity = I::BITS + 1;
                let candidate = candidate.to_upper_bits_be(num_bits_with_capacity as usize);
                assert_eq!(num_bits_with_capacity, candidate.len() as u64);
                for (i, (expected_bit, candidate_bit)) in expected.iter().zip_eq(candidate.iter().skip(1)).enumerate() {
                    assert_eq!(*expected_bit, candidate_bit.eject_value(), "MSB-{i}");
                }
                assert_count!(ToUpperBits<Boolean>() => Field, &(mode, num_bits_with_capacity));
                assert_output_mode!(ToUpperBits<Boolean>() => Field, &mode, candidate);
            });
        }
    }

    fn check_to_upper_bits_be_of_largest_value(mode: Mode) {
        let size_in_bits = console::Field::<<Circuit as Environment>::Network>::size_in_bits();
        let modulus_minus_one_bits_be = (-console::Field::<<Circuit as Environment>::Network>::one()).to_bits_be();

        for k in 1..=size_in_bits {
            // Construct the largest field element whose lower `n - k` bits are zero.
            let mut bits_be = modulus_minus_one_bits_be[..k].to_vec();
            bits_be.resize(size_in_bits, false);
            let candidate = Field::<Circuit>::new(mode, console::Field::from_bits_be(&bits_be).unwrap());

            Circuit::scope(format!("{mode} {k}"), || {
                let candidate = candidate.to_upper_bits_be(k);
                assert_eq!(modulus_minus_one_bits_be[..k], candidate.eject_value());
                assert_count!(ToUpperBits<Boolean>() => Field, &(mode, k as u64));
                assert_output_mode!(ToUpperBits<Boolean>() => Field, &mode, candidate);
            });
        }
    }

    #[test]
    fn test_to_upper_bits_of_largest_value_constant() {
        check_to_upper_bits_be_of_largest_value(Mode::Constant);
    }

    #[test]
    fn test_to_upper_bits_of_largest_value_public() {
        check_to_upper_bits_be_of_largest_value(Mode::Public);
    }

    #[test]
    fn test_to_upper_bits_of_largest_value_private() {
        check_to_upper_bits_be_of_largest_value(Mode::Private);
    }

    // 8 bits

    #[test]
    fn test_to_8_bits_constant() {
        check_to_upper_k_bits_be::<u8>(Mode::Constant); // This actually tests 9 bits.
    }

    #[test]
    fn test_to_8_bits_public() {
        check_to_upper_k_bits_be::<u8>(Mode::Public); // This actually tests 9 bits.
    }

    #[test]
    fn test_to_8_bits_private() {
        check_to_upper_k_bits_be::<u8>(Mode::Private); // This actually tests 9 bits.
    }

    // 16 bits

    #[test]
    fn test_to_16_bits_constant() {
        check_to_upper_k_bits_be::<u16>(Mode::Constant); // This actually tests 17 bits.
    }

    #[test]
    fn test_to_16_bits_public() {
        check_to_upper_k_bits_be::<u16>(Mode::Public); // This actually tests 17 bits.
    }

    #[test]
    fn test_to_16_bits_private() {
        check_to_upper_k_bits_be::<u16>(Mode::Private); // This actually tests 17 bits.
    }

    // 32 bits

    #[test]
    fn test_to_32_bits_constant() {
        check_to_upper_k_bits_be::<u32>(Mode::Constant); // This actually tests 33 bits.
    }

    #[test]
    fn test_to_32_bits_public() {
        check_to_upper_k_bits_be::<u32>(Mode::Public); // This actually tests 33 bits.
    }

    #[test]
    fn test_to_32_bits_private() {
        check_to_upper_k_bits_be::<u32>(Mode::Private); // This actually tests 33 bits.
    }

    // 64 bits

    #[test]
    fn test_to_64_bits_constant() {
        check_to_upper_k_bits_be::<u64>(Mode::Constant); // This actually tests 65 bits.
    }

    #[test]
    fn test_to_64_bits_public() {
        check_to_upper_k_bits_be::<u64>(Mode::Public); // This actually tests 65 bits.
    }

    #[test]
    fn test_to_64_bits_private() {
        check_to_upper_k_bits_be::<u64>(Mode::Private); // This actually tests 65 bits.
    }

    // 128 bits

    #[test]
    fn test_to_128_bits_constant() {
        check_to_upper_k_bits_be::<u128>(Mode::Constant); // This actually tests 129 bits.
    }

    #[test]
    fn test_to_128_bits_public() {
        check_to_upper_k_bits_be::<u128>(Mode::Public); // This actually tests 129 bits.
    }

    #[test]
    fn test_to_128_bits_private() {
        check_to_upper_k_bits_be::<u128>(Mode::Private); // This actually tests 129 bits.
    }
}
