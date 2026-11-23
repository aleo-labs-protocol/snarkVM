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

impl<E: Environment, I: IntegerType> ToFields for Integer<E, I> {
    type Field = Field<E>;

    /// Casts an integer into a list of base fields.
    fn to_fields(&self) -> Vec<Self::Field> {
        vec![self.to_field()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_to_fields<I: IntegerType>(mode: Mode, rng: &mut TestRng) {
        for i in 0..ITERATIONS {
            // Sample a random integer.
            let expected = Uniform::rand(rng);
            let candidate = Integer::<Circuit, I>::new(mode, expected);

            Circuit::scope(format!("{mode} {expected} {i}"), || {
                // Perform the operation.
                let candidate = candidate.to_fields();
                assert_eq!(1, candidate.len());
                assert_scope!(0, 0, 0, 0);

                // Extract the bits from the base field representation.
                let candidate_bits_le = candidate[0].eject_value().to_bits_le();
                assert_eq!(<Circuit as Environment>::BaseField::size_in_bits(), candidate_bits_le.len());

                // Ensure all integer bits match with the expected result.
                // Note: `unwrap()` is safe as the integer is at most 128 bits.
                let i_bits = usize::try_from(I::BITS).unwrap();
                let expected_bits = expected.to_bits_le();
                for (expected_bit, candidate_bit) in expected_bits.iter().zip_eq(&candidate_bits_le[0..i_bits]) {
                    assert_eq!(expected_bit, candidate_bit);
                }

                // Ensure all remaining bits are 0.
                for candidate_bit in &candidate_bits_le[i_bits..] {
                    assert!(!candidate_bit);
                }
            });
            Circuit::reset();
        }
    }

    #[test]
    fn test_u8_to_fields() {
        let mut rng = TestRng::default();

        type I = u8;
        check_to_fields::<I>(Mode::Constant, &mut rng);
        check_to_fields::<I>(Mode::Public, &mut rng);
        check_to_fields::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i8_to_fields() {
        let mut rng = TestRng::default();

        type I = i8;
        check_to_fields::<I>(Mode::Constant, &mut rng);
        check_to_fields::<I>(Mode::Public, &mut rng);
        check_to_fields::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u16_to_fields() {
        let mut rng = TestRng::default();

        type I = u16;
        check_to_fields::<I>(Mode::Constant, &mut rng);
        check_to_fields::<I>(Mode::Public, &mut rng);
        check_to_fields::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i16_to_fields() {
        let mut rng = TestRng::default();

        type I = i16;
        check_to_fields::<I>(Mode::Constant, &mut rng);
        check_to_fields::<I>(Mode::Public, &mut rng);
        check_to_fields::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u32_to_fields() {
        let mut rng = TestRng::default();

        type I = u32;
        check_to_fields::<I>(Mode::Constant, &mut rng);
        check_to_fields::<I>(Mode::Public, &mut rng);
        check_to_fields::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i32_to_fields() {
        let mut rng = TestRng::default();

        type I = i32;
        check_to_fields::<I>(Mode::Constant, &mut rng);
        check_to_fields::<I>(Mode::Public, &mut rng);
        check_to_fields::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u64_to_fields() {
        let mut rng = TestRng::default();

        type I = u64;
        check_to_fields::<I>(Mode::Constant, &mut rng);
        check_to_fields::<I>(Mode::Public, &mut rng);
        check_to_fields::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i64_to_fields() {
        let mut rng = TestRng::default();

        type I = i64;
        check_to_fields::<I>(Mode::Constant, &mut rng);
        check_to_fields::<I>(Mode::Public, &mut rng);
        check_to_fields::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u128_to_fields() {
        let mut rng = TestRng::default();

        type I = u128;
        check_to_fields::<I>(Mode::Constant, &mut rng);
        check_to_fields::<I>(Mode::Public, &mut rng);
        check_to_fields::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i128_to_fields() {
        let mut rng = TestRng::default();

        type I = i128;
        check_to_fields::<I>(Mode::Constant, &mut rng);
        check_to_fields::<I>(Mode::Public, &mut rng);
        check_to_fields::<I>(Mode::Private, &mut rng);
    }
}
