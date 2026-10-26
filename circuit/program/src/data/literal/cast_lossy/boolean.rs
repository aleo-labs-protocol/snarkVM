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

impl<E: Environment> CastLossy<Address<E>> for Boolean<E> {
    /// Casts a `Boolean` to an `Address`.
    /// This is safe because casting from a boolean to any other type is **always** lossless.
    ///
    /// If the boolean is true, the address is the generator of the prime-order subgroup.
    /// If the boolean is false, the address is the zero group element.
    #[inline]
    fn cast_lossy(&self) -> Address<E> {
        Address::ternary(self, &Address::from_group(Group::generator()), &Address::zero())
    }
}

impl<E: Environment> CastLossy<Boolean<E>> for Boolean<E> {
    /// Casts a `Boolean` to a `Boolean`.
    /// This is an identity cast, so it is **always** lossless.
    #[inline]
    fn cast_lossy(&self) -> Boolean<E> {
        self.clone()
    }
}

impl<E: Environment> CastLossy<Field<E>> for Boolean<E> {
    /// Casts a `Boolean` to a `Field`.
    /// This is safe because casting from a boolean to any other type is **always** lossless.
    #[inline]
    fn cast_lossy(&self) -> Field<E> {
        Field::from_boolean(self)
    }
}

impl<E: Environment> CastLossy<Group<E>> for Boolean<E> {
    /// Casts a `Boolean` to a `Group`.
    /// This is safe because casting from a boolean to any other type is **always** lossless.
    ///
    /// If the boolean is true, the group element is the generator of the prime-order subgroup.
    /// If the boolean is false, the group element is the zero group element.
    #[inline]
    fn cast_lossy(&self) -> Group<E> {
        Group::ternary(self, &Group::generator(), &Group::zero())
    }
}

impl<E: Environment, I: IntegerType> CastLossy<Integer<E, I>> for Boolean<E> {
    /// Casts a `Boolean` to an `Integer`.
    #[inline]
    fn cast_lossy(&self) -> Integer<E, I> {
        Integer::ternary(self, &Integer::one(), &Integer::zero())
    }
}

impl<E: Environment> CastLossy<Scalar<E>> for Boolean<E> {
    /// Casts a `Boolean` to a `Scalar`.
    /// This is safe because casting from a boolean to any other type is **always** lossless.
    #[inline]
    fn cast_lossy(&self) -> Scalar<E> {
        Scalar::ternary(self, &Scalar::one(), &Scalar::zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::CastLossy as _;
    use console_root::{network::MainnetV0, prelude::TestRng};
    use snarkvm_circuit_types::environment::{Circuit, Eject, Inject, Mode, UpdatableCount, count_is};

    use std::fmt::Debug;

    const ITERATIONS: usize = 2;

    fn sample_values(
        i: usize,
        mode: Mode,
        _: &mut TestRng,
    ) -> (console_root::types::Boolean<MainnetV0>, Boolean<Circuit>) {
        (console_root::types::Boolean::new(i.is_multiple_of(2)), Boolean::new(mode, i.is_multiple_of(2)))
    }

    check_cast_lossy!(cast_lossy, Boolean<Circuit>, console_root::types::Boolean::<MainnetV0>);

    #[test]
    fn test_boolean_to_address() {
        check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
            Mode::Constant,
            count_is!(10, 0, 0, 0),
        );
        check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
            Mode::Public,
            count_is!(10, 0, 0, 0),
        );
        check_cast_lossy::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
            Mode::Private,
            count_is!(10, 0, 0, 0),
        );
    }

    #[test]
    fn test_boolean_to_boolean() {
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
    fn test_boolean_to_field() {
        check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
            Mode::Constant,
            count_is!(0, 0, 0, 0),
        );
        check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
        check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_group() {
        check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
            Mode::Constant,
            count_is!(10, 0, 0, 0),
        );
        check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(Mode::Public, count_is!(10, 0, 0, 0));
        check_cast_lossy::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
            Mode::Private,
            count_is!(10, 0, 0, 0),
        );
    }

    #[test]
    fn test_boolean_to_i8() {
        check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(16, 0, 0, 0));
        check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(16, 0, 0, 0));
        check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(16, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_i16() {
        check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Constant, count_is!(32, 0, 0, 0));
        check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(32, 0, 0, 0));
        check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(32, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_i32() {
        check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Constant, count_is!(64, 0, 0, 0));
        check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(64, 0, 0, 0));
        check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(64, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_i64() {
        check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Constant, count_is!(128, 0, 0, 0));
        check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(128, 0, 0, 0));
        check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(128, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_i128() {
        check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
            Mode::Constant,
            count_is!(256, 0, 0, 0),
        );
        check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(Mode::Public, count_is!(256, 0, 0, 0));
        check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(Mode::Private, count_is!(256, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_scalar() {
        check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
            Mode::Constant,
            count_is!(2, 0, 0, 0),
        );
        check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
            Mode::Public,
            count_is!(2, 0, 0, 0),
        );
        check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
            Mode::Private,
            count_is!(2, 0, 0, 0),
        );
    }

    #[test]
    fn test_boolean_to_u8() {
        check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(16, 0, 0, 0));
        check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(16, 0, 0, 0));
        check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(16, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_u16() {
        check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Constant, count_is!(32, 0, 0, 0));
        check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(32, 0, 0, 0));
        check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(32, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_u32() {
        check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Constant, count_is!(64, 0, 0, 0));
        check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(64, 0, 0, 0));
        check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(64, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_u64() {
        check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Constant, count_is!(128, 0, 0, 0));
        check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(128, 0, 0, 0));
        check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(128, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_u128() {
        check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
            Mode::Constant,
            count_is!(256, 0, 0, 0),
        );
        check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(Mode::Public, count_is!(256, 0, 0, 0));
        check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(Mode::Private, count_is!(256, 0, 0, 0));
    }
}
