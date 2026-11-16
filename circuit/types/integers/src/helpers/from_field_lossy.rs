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

impl<E: Environment, I: IntegerType> Integer<E, I> {
    /// Casts an integer from a base field, with lossy truncation.
    ///
    /// This method is commonly used by hash-to-integer algorithms,
    /// where the hash output does not need to preserve the full base field.
    pub fn from_field_lossy(field: &Field<E>) -> Self {
        // Note: `unwrap()` is safe as the integer is at most 128 bits.
        let i_bits = usize::try_from(I::BITS).unwrap();

        debug_assert!(I::BITS < E::BaseField::size_in_bits() as u64);

        // Truncate the field to the size in bits of the integer.
        // Slicing here is safe as the base field is larger than the integer domain.
        Self { bits_le: field.to_bits_le()[..i_bits].to_vec(), phantom: Default::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_from_field_lossy<I: IntegerType>(mode: Mode, rng: &mut TestRng) {
        for i in 0..ITERATIONS {
            // Sample a random integer.
            let expected = Uniform::rand(rng);
            let candidate = Integer::<Circuit, I>::new(mode, expected).to_field();

            Circuit::scope(format!("{mode} {expected} {i}"), || {
                // Perform the operation.
                let candidate = Integer::from_field_lossy(&candidate);
                assert_eq!(expected, candidate.eject_value());
                match mode {
                    Mode::Constant => assert_scope!(0, 0, 0, 0),
                    _ => assert_scope!(0, 0, 0, 0),
                }
            });
            Circuit::reset();

            // Sample a random field.
            let expected = Field::<Circuit>::new(mode, Uniform::rand(rng));
            // Perform the operation.
            Integer::<_, I>::from_field_lossy(&expected); // This should not fail.
        }
    }

    #[test]
    fn test_u8_from_field_lossy() {
        let mut rng = TestRng::default();

        type I = u8;
        check_from_field_lossy::<I>(Mode::Constant, &mut rng);
        check_from_field_lossy::<I>(Mode::Public, &mut rng);
        check_from_field_lossy::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i8_from_field_lossy() {
        let mut rng = TestRng::default();

        type I = i8;
        check_from_field_lossy::<I>(Mode::Constant, &mut rng);
        check_from_field_lossy::<I>(Mode::Public, &mut rng);
        check_from_field_lossy::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u16_from_field_lossy() {
        let mut rng = TestRng::default();

        type I = u16;
        check_from_field_lossy::<I>(Mode::Constant, &mut rng);
        check_from_field_lossy::<I>(Mode::Public, &mut rng);
        check_from_field_lossy::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i16_from_field_lossy() {
        let mut rng = TestRng::default();

        type I = i16;
        check_from_field_lossy::<I>(Mode::Constant, &mut rng);
        check_from_field_lossy::<I>(Mode::Public, &mut rng);
        check_from_field_lossy::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u32_from_field_lossy() {
        let mut rng = TestRng::default();

        type I = u32;
        check_from_field_lossy::<I>(Mode::Constant, &mut rng);
        check_from_field_lossy::<I>(Mode::Public, &mut rng);
        check_from_field_lossy::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i32_from_field_lossy() {
        let mut rng = TestRng::default();

        type I = i32;
        check_from_field_lossy::<I>(Mode::Constant, &mut rng);
        check_from_field_lossy::<I>(Mode::Public, &mut rng);
        check_from_field_lossy::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u64_from_field_lossy() {
        let mut rng = TestRng::default();

        type I = u64;
        check_from_field_lossy::<I>(Mode::Constant, &mut rng);
        check_from_field_lossy::<I>(Mode::Public, &mut rng);
        check_from_field_lossy::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i64_from_field_lossy() {
        let mut rng = TestRng::default();

        type I = i64;
        check_from_field_lossy::<I>(Mode::Constant, &mut rng);
        check_from_field_lossy::<I>(Mode::Public, &mut rng);
        check_from_field_lossy::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u128_from_field_lossy() {
        let mut rng = TestRng::default();

        type I = u128;
        check_from_field_lossy::<I>(Mode::Constant, &mut rng);
        check_from_field_lossy::<I>(Mode::Public, &mut rng);
        check_from_field_lossy::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i128_from_field_lossy() {
        let mut rng = TestRng::default();

        type I = i128;
        check_from_field_lossy::<I>(Mode::Constant, &mut rng);
        check_from_field_lossy::<I>(Mode::Public, &mut rng);
        check_from_field_lossy::<I>(Mode::Private, &mut rng);
    }
}
