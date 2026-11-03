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

impl<E: Environment> ToLowerBits for Field<E> {
    type Boolean = Boolean<E>;

    ///
    /// Outputs the lower `k` bits of an `n`-bit field element in little-endian representation.
    /// Enforces that the upper `n - k` bits are zero.
    ///
    /// The decomposition is unique: for `k < n`, the bits encode an integer less than
    /// the modulus, and for `k == n`, the unique decomposition from `to_bits_le` is
    /// returned, which enforces that the bits are less than the modulus.
    ///
    fn to_lower_bits_le(&self, k: usize) -> Vec<Self::Boolean> {
        // Ensure the size is within the allowed capacity.
        if k > E::BaseField::size_in_bits() {
            E::halt(format!(
                "Attempted to extract {k} bits from a {}-bit base field element",
                E::BaseField::size_in_bits()
            ))
        }

        // An `n`-bit decomposition can encode integers that are at least the modulus,
        // so use the unique decomposition, which enforces that the bits are less than the modulus.
        if k == E::BaseField::size_in_bits() {
            return self.to_bits_le();
        }

        // Construct a vector of `Boolean`s comprising the bits of the field value.
        // As `k < n`, the bits encode an integer less than the modulus, so the decomposition is unique.
        let bits = witness!(|self| self.to_bits_le().into_iter().take(k).collect::<Vec<_>>());

        // Reconstruct the bits as a linear combination representing the original field value.
        let mut accumulator = Field::zero();
        let mut coefficient = Field::one();
        for bit in &bits {
            accumulator += Field::from_boolean(bit) * &coefficient;
            coefficient = coefficient.double();
        }

        // Ensure value * 1 == (2^k * b_k + ... + 2^0 * b_0)
        // and ensures that b_n, ..., b_{n-k} are all equal to zero.
        E::assert_eq(self, accumulator).expect("Field to_lower_bits constraint unsatisfied");

        bits
    }

    ///
    /// Outputs the lower `k` bits of an `n`-bit field element in big-endian representation.
    /// Enforces that the upper `n - k` bits are zero.
    ///
    /// The decomposition is unique, as this returns the little-endian decomposition in reverse order.
    ///
    fn to_lower_bits_be(&self, k: usize) -> Vec<Self::Boolean> {
        let mut bits_be = self.to_lower_bits_le(k);
        bits_be.reverse();
        bits_be
    }
}

impl<E: Environment> Metrics<dyn ToLowerBits<Boolean = Boolean<E>>> for Field<E> {
    type Case = (Mode, u64);

    fn count(case: &Self::Case) -> Count {
        match case {
            (Mode::Constant, k) => Count::is(*k, 0, 0, 0),
            (mode, k) if *k == E::BaseField::size_in_bits() as u64 => {
                count!(Field<E>, ToBits<Boolean = Boolean<E>>, mode)
            }
            (_, k) => Count::is(0, 0, *k, k + 1),
        }
    }
}

impl<E: Environment> OutputMode<dyn ToLowerBits<Boolean = Boolean<E>>> for Field<E> {
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
    fn check_to_lower_k_bits_le<I: IntegerType + Unsigned>(
        mode: Mode,
    ) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random unsigned integer.
            let value: I = Uniform::rand(&mut rng);
            let expected = value.to_bits_le();

            // Construct the unsigned integer as a field element.
            let candidate = Field::<Circuit>::new(mode, console::Field::from_bits_le(&expected).unwrap());

            Circuit::scope(format!("{mode} {i}"), || {
                let candidate = candidate.to_lower_bits_le(I::BITS as usize);
                assert_eq!(I::BITS, candidate.len() as u64);
                for (i, (expected_bit, candidate_bit)) in expected.iter().zip_eq(candidate.iter()).enumerate() {
                    assert_eq!(*expected_bit, candidate_bit.eject_value(), "LSB+{i}");
                }
                assert_count!(ToLowerBits<Boolean>() => Field, &(mode, I::BITS));
                assert_output_mode!(ToLowerBits<Boolean>() => Field, &mode, candidate);
            });
        }
    }

    fn check_to_lower_size_in_bits_le(mode: Mode) {
        let size_in_bits = console::Field::<<Circuit as Environment>::Network>::size_in_bits();

        let mut rng = TestRng::default();

        // Sample random field elements, and the largest field element.
        let values = (0..ITERATIONS).map(|_| Uniform::rand(&mut rng)).chain([-console::Field::one()]);
        for (i, expected) in values.enumerate() {
            let candidate = Field::<Circuit>::new(mode, expected);

            Circuit::scope(format!("{mode} {i}"), || {
                let candidate = candidate.to_lower_bits_le(size_in_bits);
                assert_eq!(expected.to_bits_le(), candidate.eject_value());
                assert_count!(ToLowerBits<Boolean>() => Field, &(mode, size_in_bits as u64));
                assert_output_mode!(ToLowerBits<Boolean>() => Field, &mode, candidate);
            });
        }
    }

    #[test]
    fn test_to_size_in_bits_constant() {
        check_to_lower_size_in_bits_le(Mode::Constant);
    }

    #[test]
    fn test_to_size_in_bits_public() {
        check_to_lower_size_in_bits_le(Mode::Public);
    }

    #[test]
    fn test_to_size_in_bits_private() {
        check_to_lower_size_in_bits_le(Mode::Private);
    }

    // 8 bits

    #[test]
    fn test_to_8_bits_constant() {
        check_to_lower_k_bits_le::<u8>(Mode::Constant);
    }

    #[test]
    fn test_to_8_bits_public() {
        check_to_lower_k_bits_le::<u8>(Mode::Public);
    }

    #[test]
    fn test_to_8_bits_private() {
        check_to_lower_k_bits_le::<u8>(Mode::Private);
    }

    // 16 bits

    #[test]
    fn test_to_16_bits_constant() {
        check_to_lower_k_bits_le::<u16>(Mode::Constant);
    }

    #[test]
    fn test_to_16_bits_public() {
        check_to_lower_k_bits_le::<u16>(Mode::Public);
    }

    #[test]
    fn test_to_16_bits_private() {
        check_to_lower_k_bits_le::<u16>(Mode::Private);
    }

    // 32 bits

    #[test]
    fn test_to_32_bits_constant() {
        check_to_lower_k_bits_le::<u32>(Mode::Constant);
    }

    #[test]
    fn test_to_32_bits_public() {
        check_to_lower_k_bits_le::<u32>(Mode::Public);
    }

    #[test]
    fn test_to_32_bits_private() {
        check_to_lower_k_bits_le::<u32>(Mode::Private);
    }

    // 64 bits

    #[test]
    fn test_to_64_bits_constant() {
        check_to_lower_k_bits_le::<u64>(Mode::Constant);
    }

    #[test]
    fn test_to_64_bits_public() {
        check_to_lower_k_bits_le::<u64>(Mode::Public);
    }

    #[test]
    fn test_to_64_bits_private() {
        check_to_lower_k_bits_le::<u64>(Mode::Private);
    }

    // 128 bits

    #[test]
    fn test_to_128_bits_constant() {
        check_to_lower_k_bits_le::<u128>(Mode::Constant);
    }

    #[test]
    fn test_to_128_bits_public() {
        check_to_lower_k_bits_le::<u128>(Mode::Public);
    }

    #[test]
    fn test_to_128_bits_private() {
        check_to_lower_k_bits_le::<u128>(Mode::Private);
    }
}
