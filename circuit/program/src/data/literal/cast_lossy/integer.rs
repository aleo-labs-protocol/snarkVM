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

impl<E: Environment, I: IntegerType> CastLossy<Address<E>> for Integer<E, I> {
    /// Casts an `Integer` to an `Address`.
    ///
    /// This operation converts the integer into a field element, and then attempts to recover
    /// the group element to construct the address. See the documentation of `Field::cast_lossy`
    /// on the `Group` type for more details.
    #[inline]
    fn cast_lossy(&self) -> Address<E> {
        let field: Field<E> = self.cast_lossy();
        field.cast_lossy()
    }
}

impl<E: Environment, I: IntegerType> CastLossy<Boolean<E>> for Integer<E, I> {
    /// Casts an `Integer` to a `Boolean`, with lossy truncation.
    /// This operation returns the least significant bit of the field.
    #[inline]
    fn cast_lossy(&self) -> Boolean<E> {
        let bits_le = self.to_bits_le();
        debug_assert!(!bits_le.is_empty(), "An integer must have at least one bit");
        bits_le[0].clone()
    }
}

impl<E: Environment, I: IntegerType> CastLossy<Field<E>> for Integer<E, I> {
    /// Casts an `Integer` to a `Field`.
    /// This is safe because casting from an integer to a field is **always** lossless.
    #[inline]
    fn cast_lossy(&self) -> Field<E> {
        self.to_field()
    }
}

impl<E: Environment, I: IntegerType> CastLossy<Group<E>> for Integer<E, I> {
    /// Casts an `Integer` to a `Group`.
    ///
    /// This operation converts the integer into a field element, and then attempts to recover
    /// the group element. See the documentation of `Field::cast_lossy` on the `Group` type
    /// for more details.
    #[inline]
    fn cast_lossy(&self) -> Group<E> {
        let field: Field<E> = self.cast_lossy();
        field.cast_lossy()
    }
}

impl<E: Environment, I0: IntegerType, I1: IntegerType> CastLossy<Integer<E, I1>> for Integer<E, I0> {
    /// Casts an `Integer` to an `Integer` of a different type, with lossy truncation.
    // Note: `IntegerType::BITS` is at most 128, so the cast to `usize` is lossless.
    #[allow(clippy::cast_possible_truncation)]
    fn cast_lossy(&self) -> Integer<E, I1> {
        let mut bits_le = self.to_bits_le();
        // If the source type is smaller than the destination type, then perform the appropriate extension.
        let padding = match I0::is_signed() {
            // If the source type is signed, then sign extend.
            true => self.msb().clone(),
            // Otherwise, zero extend.
            false => Boolean::constant(false),
        };
        bits_le.resize(I1::BITS as usize, padding);
        // Construct the integer from the bits.
        Integer::from_bits_le(&bits_le)
    }
}

impl<E: Environment, I: IntegerType> CastLossy<Scalar<E>> for Integer<E, I> {
    /// Casts an `Integer` to a `Scalar`.
    /// This is safe because casting from an integer to a scalar is **always** lossless.
    #[inline]
    fn cast_lossy(&self) -> Scalar<E> {
        self.to_scalar()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::CastLossy as _;
    use console_root::{
        network::MainnetV0,
        prelude::{One, TestRng, Uniform, Zero},
    };
    use snarkvm_circuit_types::environment::{Circuit, Eject, Inject, Mode, UpdatableCount, count_is, count_less_than};

    use std::fmt::Debug;

    const ITERATIONS: usize = 10;

    fn sample_values<I: IntegerType>(
        i: usize,
        mode: Mode,
        rng: &mut TestRng,
    ) -> (console_root::types::integers::Integer<MainnetV0, I>, Integer<Circuit, I>) {
        let console_value = match i {
            0 => console_root::types::integers::Integer::<MainnetV0, I>::zero(),
            1 => console_root::types::integers::Integer::<MainnetV0, I>::one(),
            2 => console_root::types::integers::Integer::<MainnetV0, I>::new(I::MAX),
            3 => console_root::types::integers::Integer::<MainnetV0, I>::new(I::MIN),
            4 if I::is_signed() => -console_root::types::integers::Integer::<MainnetV0, I>::one(),
            _ => Uniform::rand(rng),
        };
        let circuit_value = Integer::<Circuit, I>::new(mode, console_value);
        (console_value, circuit_value)
    }

    mod i8 {
        use super::*;

        fn sample_values(i: usize, mode: Mode, rng: &mut TestRng) -> (console_root::types::I8<MainnetV0>, I8<Circuit>) {
            super::sample_values(i, mode, rng)
        }

        check_cast_lossy!(cast_lossy, I8<Circuit>, console_root::types::I8<MainnetV0>);

        #[test]
        fn test_i8_to_address() {
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_i8_to_boolean() {
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i8_to_field() {
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i8_to_group() {
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_i8_to_i8() {
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i8_to_i16() {
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i8_to_i32() {
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i8_to_i64() {
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i8_to_i128() {
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i8_to_scalar() {
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i8_to_u8() {
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i8_to_u16() {
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i8_to_u32() {
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i8_to_u64() {
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i8_to_u128() {
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }
    }

    mod i16 {
        use super::*;

        fn sample_values(
            i: usize,
            mode: Mode,
            rng: &mut TestRng,
        ) -> (console_root::types::I16<MainnetV0>, I16<Circuit>) {
            super::sample_values(i, mode, rng)
        }

        check_cast_lossy!(cast_lossy, I16<Circuit>, console_root::types::I16<MainnetV0>);

        #[test]
        fn test_i16_to_address() {
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_i16_to_boolean() {
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i16_to_field() {
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i16_to_group() {
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_i16_to_i8() {
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i16_to_i16() {
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i16_to_i32() {
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i16_to_i64() {
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i16_to_i128() {
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i16_to_scalar() {
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i16_to_u8() {
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i16_to_u16() {
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i16_to_u32() {
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i16_to_u64() {
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i16_to_u128() {
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }
    }

    mod i32 {
        use super::*;

        fn sample_values(
            i: usize,
            mode: Mode,
            rng: &mut TestRng,
        ) -> (console_root::types::I32<MainnetV0>, I32<Circuit>) {
            super::sample_values(i, mode, rng)
        }

        check_cast_lossy!(cast_lossy, I32<Circuit>, console_root::types::I32<MainnetV0>);

        #[test]
        fn test_i32_to_address() {
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_i32_to_boolean() {
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i32_to_field() {
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i32_to_group() {
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_i32_to_i8() {
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i32_to_i16() {
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i32_to_i32() {
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i32_to_i64() {
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i32_to_i128() {
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i32_to_scalar() {
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i32_to_u8() {
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i32_to_u16() {
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i32_to_u32() {
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i32_to_u64() {
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i32_to_u128() {
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }
    }

    mod i64 {
        use super::*;

        fn sample_values(
            i: usize,
            mode: Mode,
            rng: &mut TestRng,
        ) -> (console_root::types::I64<MainnetV0>, I64<Circuit>) {
            super::sample_values(i, mode, rng)
        }

        check_cast_lossy!(cast_lossy, I64<Circuit>, console_root::types::I64<MainnetV0>);

        #[test]
        fn test_i64_to_address() {
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_i64_to_boolean() {
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i64_to_field() {
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i64_to_group() {
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_i64_to_i8() {
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i64_to_i16() {
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i64_to_i32() {
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i64_to_i64() {
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i64_to_i128() {
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i64_to_scalar() {
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i64_to_u8() {
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i64_to_u16() {
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i64_to_u32() {
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i64_to_u64() {
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i64_to_u128() {
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }
    }

    mod i128 {
        use super::*;

        fn sample_values(
            i: usize,
            mode: Mode,
            rng: &mut TestRng,
        ) -> (console_root::types::I128<MainnetV0>, I128<Circuit>) {
            super::sample_values(i, mode, rng)
        }

        check_cast_lossy!(cast_lossy, I128<Circuit>, console_root::types::I128<MainnetV0>);

        #[test]
        fn test_i128_to_address() {
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_i128_to_boolean() {
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i128_to_field() {
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i128_to_group() {
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_i128_to_i8() {
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i128_to_i16() {
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i128_to_i32() {
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i128_to_i64() {
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i128_to_i128() {
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i128_to_scalar() {
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_i128_to_u8() {
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i128_to_u16() {
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i128_to_u32() {
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i128_to_u64() {
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_i128_to_u128() {
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }
    }

    mod u8 {
        use super::*;

        fn sample_values(i: usize, mode: Mode, rng: &mut TestRng) -> (console_root::types::U8<MainnetV0>, U8<Circuit>) {
            super::sample_values(i, mode, rng)
        }

        check_cast_lossy!(cast_lossy, U8<Circuit>, console_root::types::U8<MainnetV0>);

        #[test]
        fn test_u8_to_address() {
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_u8_to_boolean() {
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u8_to_field() {
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u8_to_group() {
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_u8_to_i8() {
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u8_to_i16() {
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u8_to_i32() {
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u8_to_i64() {
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u8_to_i128() {
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u8_to_scalar() {
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u8_to_u8() {
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u8_to_u16() {
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u8_to_u32() {
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u8_to_u64() {
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u8_to_u128() {
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }
    }

    mod u16 {
        use super::*;

        fn sample_values(
            i: usize,
            mode: Mode,
            rng: &mut TestRng,
        ) -> (console_root::types::U16<MainnetV0>, U16<Circuit>) {
            super::sample_values(i, mode, rng)
        }

        check_cast_lossy!(cast_lossy, U16<Circuit>, console_root::types::U16<MainnetV0>);

        #[test]
        fn test_u16_to_address() {
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_u16_to_boolean() {
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u16_to_field() {
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u16_to_group() {
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_u16_to_i8() {
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u16_to_i16() {
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u16_to_i32() {
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u16_to_i64() {
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u16_to_i128() {
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u16_to_scalar() {
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u16_to_u8() {
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u16_to_u16() {
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u16_to_u32() {
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u16_to_u64() {
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u16_to_u128() {
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }
    }

    mod u32 {
        use super::*;

        fn sample_values(
            i: usize,
            mode: Mode,
            rng: &mut TestRng,
        ) -> (console_root::types::U32<MainnetV0>, U32<Circuit>) {
            super::sample_values(i, mode, rng)
        }

        check_cast_lossy!(cast_lossy, U32<Circuit>, console_root::types::U32<MainnetV0>);

        #[test]
        fn test_u32_to_address() {
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_u32_to_boolean() {
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u32_to_field() {
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u32_to_group() {
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_u32_to_i8() {
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u32_to_i16() {
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u32_to_i32() {
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u32_to_i64() {
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u32_to_i128() {
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u32_to_scalar() {
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u32_to_u8() {
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u32_to_u16() {
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u32_to_u32() {
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u32_to_u64() {
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u32_to_u128() {
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }
    }

    mod u64 {
        use super::*;

        fn sample_values(
            i: usize,
            mode: Mode,
            rng: &mut TestRng,
        ) -> (console_root::types::U64<MainnetV0>, U64<Circuit>) {
            super::sample_values(i, mode, rng)
        }

        check_cast_lossy!(cast_lossy, U64<Circuit>, console_root::types::U64<MainnetV0>);

        #[test]
        fn test_u64_to_address() {
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_u64_to_boolean() {
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u64_to_field() {
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u64_to_group() {
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_u64_to_i8() {
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u64_to_i16() {
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u64_to_i32() {
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u64_to_i64() {
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u64_to_i128() {
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u64_to_scalar() {
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u64_to_u8() {
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u64_to_u16() {
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u64_to_u32() {
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u64_to_u64() {
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u64_to_u128() {
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }
    }

    mod u128 {
        use super::*;

        fn sample_values(
            i: usize,
            mode: Mode,
            rng: &mut TestRng,
        ) -> (console_root::types::U128<MainnetV0>, U128<Circuit>) {
            super::sample_values(i, mode, rng)
        }

        check_cast_lossy!(cast_lossy, U128<Circuit>, console_root::types::U128<MainnetV0>);

        #[test]
        fn test_u128_to_address() {
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_u128_to_boolean() {
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u128_to_field() {
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u128_to_group() {
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Constant,
                count_less_than!(4303, 0, 0, 0),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Public,
                count_is!(2029, 0, 6745, 6750),
            );
            check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
                Mode::Private,
                count_is!(2029, 0, 6745, 6750),
            );
        }

        #[test]
        fn test_u128_to_i8() {
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u128_to_i16() {
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u128_to_i32() {
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u128_to_i64() {
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u128_to_i128() {
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u128_to_scalar() {
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }

        #[test]
        fn test_u128_to_u8() {
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u128_to_u16() {
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u128_to_u32() {
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u128_to_u64() {
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
            check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
        }

        #[test]
        fn test_u128_to_u128() {
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Constant,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Public,
                count_is!(0, 0, 0, 0),
            );
            check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
                Mode::Private,
                count_is!(0, 0, 0, 0),
            );
        }
    }
}
