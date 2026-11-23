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

impl<E: Environment> CastLossy<Address<E>> for Scalar<E> {
    /// Casts a `Scalar` to an `Address`.
    ///
    /// This operation converts the scalar into a field element, and then attempts to recover
    /// the group element to construct the address. See the documentation of `Field::cast_lossy`
    /// on the `Group` type for more details.
    #[inline]
    fn cast_lossy(&self) -> Address<E> {
        let field: Field<E> = self.cast_lossy();
        field.cast_lossy()
    }
}

impl<E: Environment> CastLossy<Boolean<E>> for Scalar<E> {
    /// Casts a `Scalar` to a `Boolean`, with lossy truncation.
    /// This operation returns the least significant bit of the scalar.
    #[inline]
    fn cast_lossy(&self) -> Boolean<E> {
        let bits_le = self.to_bits_le();
        debug_assert!(!bits_le.is_empty(), "An integer must have at least one bit");
        bits_le[0].clone()
    }
}

impl<E: Environment> CastLossy<Group<E>> for Scalar<E> {
    /// Casts a `Scalar` to a `Group`.
    ///
    /// This operation converts the scalar into a field element, and then attempts to recover
    /// the group element. See the documentation of `Field::cast_lossy` on the `Group` type
    /// for more details.
    #[inline]
    fn cast_lossy(&self) -> Group<E> {
        let field: Field<E> = self.cast_lossy();
        field.cast_lossy()
    }
}

impl<E: Environment> CastLossy<Field<E>> for Scalar<E> {
    /// Casts a `Scalar` to a `Field`.
    /// This operation is **always** lossless.
    #[inline]
    fn cast_lossy(&self) -> Field<E> {
        self.to_field()
    }
}

impl<E: Environment, I: IntegerType> CastLossy<Integer<E, I>> for Scalar<E> {
    /// Casts a `Scalar` to an `Integer`, with lossy truncation.
    #[inline]
    fn cast_lossy(&self) -> Integer<E, I> {
        debug_assert!(I::BITS < <console::Scalar<E::Network> as console::SizeInBits>::size_in_bits() as u64);

        // Truncate the field to the size of the integer domain.
        // Slicing here is safe as the base field is larger than the integer domain.
        Integer::<E, I>::from_bits_le(&self.to_bits_le()[..usize::try_from(I::BITS).unwrap()])
    }
}

impl<E: Environment> CastLossy<Scalar<E>> for Scalar<E> {
    /// Casts a `Scalar` to a `Scalar`.
    /// This is an identity cast, so it is **always** lossless.
    #[inline]
    fn cast_lossy(&self) -> Scalar<E> {
        self.clone()
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
    use snarkvm_circuit_types::environment::{Circuit, Eject, Inject, Mode, UpdatableCount, count_is};

    use std::fmt::Debug;

    const ITERATIONS: usize = 10;

    fn sample_values(
        i: usize,
        mode: Mode,
        rng: &mut TestRng,
    ) -> (console_root::types::Scalar<MainnetV0>, Scalar<Circuit>) {
        let console_value = match i {
            0 => console_root::types::Scalar::<MainnetV0>::zero(),
            1 => console_root::types::Scalar::<MainnetV0>::one(),
            _ => Uniform::rand(rng),
        };
        let circuit_value = Scalar::<Circuit>::new(mode, console_value);
        (console_value, circuit_value)
    }

    check_cast_lossy!(cast_lossy, Scalar<Circuit>, console_root::types::Scalar::<MainnetV0>);

    #[test]
    fn test_scalar_to_address() {
        check_constant_cast_lossy_to_group!(Address<Circuit>, console_root::types::Address<MainnetV0>);
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
    fn test_scalar_to_boolean() {
        check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
            Mode::Constant,
            count_is!(251, 0, 0, 0),
        );
        check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
            Mode::Public,
            count_is!(0, 0, 501, 503),
        );
        check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
            Mode::Private,
            count_is!(0, 0, 501, 503),
        );
    }

    #[test]
    fn test_scalar_to_field() {
        check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
            Mode::Constant,
            count_is!(0, 0, 0, 0),
        );
        check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
        check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
    }

    #[test]
    fn test_scalar_to_group() {
        check_constant_cast_lossy_to_group!(Group<Circuit>, console_root::types::Group<MainnetV0>);
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
    fn test_scalar_to_i8() {
        check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(251, 0, 0, 0));
        check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 501, 503));
        check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 501, 503));
    }

    #[test]
    fn test_scalar_to_i16() {
        check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Constant, count_is!(251, 0, 0, 0));
        check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 501, 503));
        check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 501, 503));
    }

    #[test]
    fn test_scalar_to_i32() {
        check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Constant, count_is!(251, 0, 0, 0));
        check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 501, 503));
        check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 501, 503));
    }

    #[test]
    fn test_scalar_to_i64() {
        check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Constant, count_is!(251, 0, 0, 0));
        check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 501, 503));
        check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 501, 503));
    }

    #[test]
    fn test_scalar_to_i128() {
        check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
            Mode::Constant,
            count_is!(251, 0, 0, 0),
        );
        check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
            Mode::Public,
            count_is!(0, 0, 501, 503),
        );
        check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
            Mode::Private,
            count_is!(0, 0, 501, 503),
        );
    }

    #[test]
    fn test_scalar_to_scalar() {
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
    fn test_scalar_to_u8() {
        check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(251, 0, 0, 0));
        check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 501, 503));
        check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 501, 503));
    }

    #[test]
    fn test_scalar_to_u16() {
        check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Constant, count_is!(251, 0, 0, 0));
        check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 501, 503));
        check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 501, 503));
    }

    #[test]
    fn test_scalar_to_u32() {
        check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Constant, count_is!(251, 0, 0, 0));
        check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 501, 503));
        check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 501, 503));
    }

    #[test]
    fn test_scalar_to_u64() {
        check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Constant, count_is!(251, 0, 0, 0));
        check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 501, 503));
        check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 501, 503));
    }

    #[test]
    fn test_scalar_to_u128() {
        check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
            Mode::Constant,
            count_is!(251, 0, 0, 0),
        );
        check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
            Mode::Public,
            count_is!(0, 0, 501, 503),
        );
        check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
            Mode::Private,
            count_is!(0, 0, 501, 503),
        );
    }
}
