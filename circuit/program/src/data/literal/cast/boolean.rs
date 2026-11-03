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

impl<E: Environment> Cast<Address<E>> for Boolean<E> {
    /// Casts a `Boolean` to an `Address`.
    #[inline]
    fn cast(&self) -> Address<E> {
        self.cast_lossy()
    }
}

impl<E: Environment> Cast<Boolean<E>> for Boolean<E> {
    /// Casts a `Boolean` to a `Boolean`.
    #[inline]
    fn cast(&self) -> Boolean<E> {
        self.cast_lossy()
    }
}

impl<E: Environment> Cast<Field<E>> for Boolean<E> {
    /// Casts a `Boolean` to a `Field`.
    #[inline]
    fn cast(&self) -> Field<E> {
        self.cast_lossy()
    }
}

impl<E: Environment> Cast<Group<E>> for Boolean<E> {
    /// Casts a `Boolean` to a `Group`.
    #[inline]
    fn cast(&self) -> Group<E> {
        self.cast_lossy()
    }
}

impl<E: Environment, I: IntegerType> Cast<Integer<E, I>> for Boolean<E> {
    /// Casts a `Boolean` to an `Integer`.
    #[inline]
    fn cast(&self) -> Integer<E, I> {
        self.cast_lossy()
    }
}

impl<E: Environment> Cast<Scalar<E>> for Boolean<E> {
    /// Casts a `Boolean` to a `Scalar`.
    #[inline]
    fn cast(&self) -> Scalar<E> {
        self.cast_lossy()
    }
}

impl<E: Environment> Cast<IdentifierLiteral<E>> for Boolean<E> {
    /// Casts a `Boolean` to an `IdentifierLiteral`.
    ///
    /// Note: This cast always fails because valid identifier literals cannot map
    /// to boolean values (0x00 or 0x01). The byte 0x00 is null and 0x01 (SOH) is
    /// not a valid identifier character. This implementation exists for uniformity
    /// with the `impl_cast_body!` macro used by all literal types.
    #[inline]
    fn cast(&self) -> IdentifierLiteral<E> {
        let field: Field<E> = self.cast();
        field.cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::Cast as _;
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

    impl_check_cast!(cast, Boolean<Circuit>, console_root::types::Boolean::<MainnetV0>);

    #[test]
    fn test_boolean_to_address() {
        check_cast::<Address<Circuit>, console_root::types::Address<MainnetV0>>(Mode::Constant, count_is!(10, 0, 0, 0));
        check_cast::<Address<Circuit>, console_root::types::Address<MainnetV0>>(Mode::Public, count_is!(10, 0, 0, 0));
        check_cast::<Address<Circuit>, console_root::types::Address<MainnetV0>>(Mode::Private, count_is!(10, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_boolean() {
        check_cast::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
        check_cast::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
        check_cast::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_field() {
        check_cast::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
        check_cast::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
        check_cast::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_group() {
        check_cast::<Group<Circuit>, console_root::types::Group<MainnetV0>>(Mode::Constant, count_is!(10, 0, 0, 0));
        check_cast::<Group<Circuit>, console_root::types::Group<MainnetV0>>(Mode::Public, count_is!(10, 0, 0, 0));
        check_cast::<Group<Circuit>, console_root::types::Group<MainnetV0>>(Mode::Private, count_is!(10, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_i8() {
        check_cast::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(16, 0, 0, 0));
        check_cast::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(16, 0, 0, 0));
        check_cast::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(16, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_i16() {
        check_cast::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Constant, count_is!(32, 0, 0, 0));
        check_cast::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(32, 0, 0, 0));
        check_cast::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(32, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_i32() {
        check_cast::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Constant, count_is!(64, 0, 0, 0));
        check_cast::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(64, 0, 0, 0));
        check_cast::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(64, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_i64() {
        check_cast::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Constant, count_is!(128, 0, 0, 0));
        check_cast::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(128, 0, 0, 0));
        check_cast::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(128, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_i128() {
        check_cast::<I128<Circuit>, console_root::types::I128<MainnetV0>>(Mode::Constant, count_is!(256, 0, 0, 0));
        check_cast::<I128<Circuit>, console_root::types::I128<MainnetV0>>(Mode::Public, count_is!(256, 0, 0, 0));
        check_cast::<I128<Circuit>, console_root::types::I128<MainnetV0>>(Mode::Private, count_is!(256, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_scalar() {
        check_cast::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(Mode::Constant, count_is!(2, 0, 0, 0));
        check_cast::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(Mode::Public, count_is!(2, 0, 0, 0));
        check_cast::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(Mode::Private, count_is!(2, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_u8() {
        check_cast::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(16, 0, 0, 0));
        check_cast::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(16, 0, 0, 0));
        check_cast::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(16, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_u16() {
        check_cast::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Constant, count_is!(32, 0, 0, 0));
        check_cast::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(32, 0, 0, 0));
        check_cast::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(32, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_u32() {
        check_cast::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Constant, count_is!(64, 0, 0, 0));
        check_cast::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(64, 0, 0, 0));
        check_cast::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(64, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_u64() {
        check_cast::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Constant, count_is!(128, 0, 0, 0));
        check_cast::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(128, 0, 0, 0));
        check_cast::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(128, 0, 0, 0));
    }

    #[test]
    fn test_boolean_to_u128() {
        check_cast::<U128<Circuit>, console_root::types::U128<MainnetV0>>(Mode::Constant, count_is!(256, 0, 0, 0));
        check_cast::<U128<Circuit>, console_root::types::U128<MainnetV0>>(Mode::Public, count_is!(256, 0, 0, 0));
        check_cast::<U128<Circuit>, console_root::types::U128<MainnetV0>>(Mode::Private, count_is!(256, 0, 0, 0));
    }
}
