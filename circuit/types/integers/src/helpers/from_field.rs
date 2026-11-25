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

impl<E: Environment, I: IntegerType> FromField for Integer<E, I> {
    type Field = Field<E>;

    /// Casts an integer from a base field.
    ///
    /// This method guarantees the following:
    ///   1. If the field element is larger than the integer domain, then the operation will fail.
    ///   2. If the field element is smaller than the integer domain, then the operation will succeed.
    fn from_field(field: Self::Field) -> Self {
        // Note: `unwrap()` is safe as the integer is at most 128 bits.
        let i_bits = usize::try_from(I::BITS).unwrap();

        // Note: We are reconstituting the integer from the base field.
        // This is safe as the number of bits in the integer is less than the base field modulus,
        // and thus will always fit within a single base field element.
        debug_assert!(I::BITS < E::BaseField::size_in_bits() as u64);

        // Extract the integer bits from the field element, **without** a carry bit.
        let bits_le = field.to_lower_bits_le(i_bits);

        // Return the integer.
        Integer { bits_le, phantom: Default::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_from_field<I: IntegerType>(mode: Mode, rng: &mut TestRng) {
        for i in 0..ITERATIONS {
            // Sample a random integer.
            let expected = Uniform::rand(rng);
            let candidate = Integer::<Circuit, I>::new(mode, expected).to_field();

            Circuit::scope(format!("{mode} {expected} {i}"), || {
                // Perform the operation.
                let candidate = Integer::from_field(candidate);
                assert_eq!(expected, candidate.eject_value());
                match mode {
                    Mode::Constant => assert_scope!(I::BITS, 0, 0, 0),
                    _ => assert_scope!(0, 0, I::BITS, I::BITS + 1),
                }
            });
            Circuit::reset();

            // Sample a random field.
            let expected = Field::<Circuit>::new(mode, Uniform::rand(rng));
            // Determine the integer domain.
            let integer_max = match I::type_name() {
                "u8" | "i8" => console::Field::<<Circuit as Environment>::Network>::from_u8(u8::MAX),
                "u16" | "i16" => console::Field::<<Circuit as Environment>::Network>::from_u16(u16::MAX),
                "u32" | "i32" => console::Field::<<Circuit as Environment>::Network>::from_u32(u32::MAX),
                "u64" | "i64" => console::Field::<<Circuit as Environment>::Network>::from_u64(u64::MAX),
                "u128" | "i128" => console::Field::<<Circuit as Environment>::Network>::from_u128(u128::MAX),
                _ => panic!("Unsupported integer type."),
            };
            // Filter for field elements that exceed the integer domain.
            if expected.eject_value() > integer_max {
                // Perform the operation.
                let result = std::panic::catch_unwind(|| {
                    Integer::<_, I>::from_field(expected); // This should fail.
                });
                assert!(result.is_err() || !Circuit::is_satisfied());
            } else {
                // Perform the operation.
                Integer::<_, I>::from_field(expected); // This should not fail.
            }
        }
    }

    #[test]
    fn test_u8_from_field() {
        let mut rng = TestRng::default();

        type I = u8;
        check_from_field::<I>(Mode::Constant, &mut rng);
        check_from_field::<I>(Mode::Public, &mut rng);
        check_from_field::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i8_from_field() {
        let mut rng = TestRng::default();

        type I = i8;
        check_from_field::<I>(Mode::Constant, &mut rng);
        check_from_field::<I>(Mode::Public, &mut rng);
        check_from_field::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u16_from_field() {
        let mut rng = TestRng::default();

        type I = u16;
        check_from_field::<I>(Mode::Constant, &mut rng);
        check_from_field::<I>(Mode::Public, &mut rng);
        check_from_field::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i16_from_field() {
        let mut rng = TestRng::default();

        type I = i16;
        check_from_field::<I>(Mode::Constant, &mut rng);
        check_from_field::<I>(Mode::Public, &mut rng);
        check_from_field::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u32_from_field() {
        let mut rng = TestRng::default();

        type I = u32;
        check_from_field::<I>(Mode::Constant, &mut rng);
        check_from_field::<I>(Mode::Public, &mut rng);
        check_from_field::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i32_from_field() {
        let mut rng = TestRng::default();

        type I = i32;
        check_from_field::<I>(Mode::Constant, &mut rng);
        check_from_field::<I>(Mode::Public, &mut rng);
        check_from_field::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u64_from_field() {
        let mut rng = TestRng::default();

        type I = u64;
        check_from_field::<I>(Mode::Constant, &mut rng);
        check_from_field::<I>(Mode::Public, &mut rng);
        check_from_field::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i64_from_field() {
        let mut rng = TestRng::default();

        type I = i64;
        check_from_field::<I>(Mode::Constant, &mut rng);
        check_from_field::<I>(Mode::Public, &mut rng);
        check_from_field::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_u128_from_field() {
        let mut rng = TestRng::default();

        type I = u128;
        check_from_field::<I>(Mode::Constant, &mut rng);
        check_from_field::<I>(Mode::Public, &mut rng);
        check_from_field::<I>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_i128_from_field() {
        let mut rng = TestRng::default();

        type I = i128;
        check_from_field::<I>(Mode::Constant, &mut rng);
        check_from_field::<I>(Mode::Public, &mut rng);
        check_from_field::<I>(Mode::Private, &mut rng);
    }
}
