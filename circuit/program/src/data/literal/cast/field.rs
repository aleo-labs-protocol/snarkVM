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

impl<E: Environment> Cast<Address<E>> for Field<E> {
    /// Casts a `Field` to an `Address`.
    ///
    /// This operation attempts to recover the group element from the field element, and then
    /// constructs an address from the group element.
    ///
    /// To cast arbitrary field elements to addresses, use `Field::cast_lossy`.
    #[inline]
    fn cast(&self) -> Address<E> {
        Address::from_field(self.clone())
    }
}

impl<E: Environment> Cast<Boolean<E>> for Field<E> {
    /// Casts a `Field` to a `Boolean`, if the field is zero or one.
    ///
    /// To cast arbitrary field elements to booleans, use `Field::cast_lossy`.
    #[inline]
    fn cast(&self) -> Boolean<E> {
        let is_one = self.is_one();
        E::assert(self.is_zero().bitor(&is_one)).expect("Field must be zero or one to cast to Boolean");
        is_one
    }
}

impl<E: Environment> Cast<Field<E>> for Field<E> {
    /// Casts a `Field` to a `Field`.
    #[inline]
    fn cast(&self) -> Field<E> {
        self.clone()
    }
}

impl<E: Environment> Cast<Group<E>> for Field<E> {
    /// Casts a `Field` to a `Group`.
    ///
    /// This operation attempts to recover the group element from the field element,
    /// and returns an error if the field element is not a valid x-coordinate.
    ///
    /// To cast arbitrary field elements to groups, use `Field::cast_lossy`.
    #[inline]
    fn cast(&self) -> Group<E> {
        Group::from_x_coordinate(self.clone())
    }
}

impl<E: Environment, I: IntegerType> Cast<Integer<E, I>> for Field<E> {
    /// Casts a `Field` to an `Integer`, if the field element is in the integer's range.
    ///
    /// To cast arbitrary field elements to integers, use `Field::cast_lossy`.
    #[inline]
    fn cast(&self) -> Integer<E, I> {
        Integer::from_field(self.clone())
    }
}

impl<E: Environment> Cast<Scalar<E>> for Field<E> {
    /// Casts a `Field` to a `Scalar`, if the field element is in the scalar's range.
    ///
    /// To cast arbitrary field elements to scalars, use `Field::cast_lossy`.
    #[inline]
    fn cast(&self) -> Scalar<E> {
        Scalar::from_field(self.clone())
    }
}

impl<E: Environment> Cast<IdentifierLiteral<E>> for Field<E> {
    /// Casts a `Field` to an `IdentifierLiteral`.
    ///
    /// This operation validates that the field element represents a valid identifier literal.
    #[inline]
    fn cast(&self) -> IdentifierLiteral<E> {
        IdentifierLiteral::from_field(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::Cast as _;
    use console_root::{
        network::MainnetV0,
        prelude::{One, TestRng, Uniform, Zero},
    };
    use snarkvm_circuit_types::environment::{Circuit, Eject, Inject, Mode, UpdatableCount, count_is, count_less_than};

    use std::fmt::Debug;

    const ITERATIONS: usize = 10;

    fn sample_values(
        i: usize,
        mode: Mode,
        rng: &mut TestRng,
    ) -> (console_root::types::Field<MainnetV0>, Field<Circuit>) {
        let console_value = match i {
            0 => console_root::types::Field::<MainnetV0>::zero(),
            1 => console_root::types::Field::<MainnetV0>::one(),
            _ => Uniform::rand(rng),
        };
        let circuit_value = Field::<Circuit>::new(mode, console_value);
        (console_value, circuit_value)
    }

    impl_check_cast!(cast, Field<Circuit>, console_root::types::Field::<MainnetV0>);

    #[test]
    fn test_field_to_address() {
        check_cast::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
            Mode::Constant,
            count_less_than!(11, 0, 0, 0),
        );
        check_cast::<Address<Circuit>, console_root::types::Address<MainnetV0>>(Mode::Public, count_is!(4, 0, 13, 13));
        check_cast::<Address<Circuit>, console_root::types::Address<MainnetV0>>(Mode::Private, count_is!(4, 0, 13, 13));
    }

    #[test]
    fn test_field_to_boolean() {
        check_cast::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(Mode::Constant, count_is!(2, 0, 0, 0));
        check_cast::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(Mode::Public, count_is!(0, 0, 5, 6));
        check_cast::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(Mode::Private, count_is!(0, 0, 5, 6));
    }

    #[test]
    fn test_field_to_field() {
        check_cast::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Constant, count_is!(0, 0, 0, 0));
        check_cast::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
        check_cast::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
    }

    #[test]
    fn test_field_to_group() {
        check_cast::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
            Mode::Constant,
            count_less_than!(11, 0, 0, 0),
        );
        check_cast::<Group<Circuit>, console_root::types::Group<MainnetV0>>(Mode::Public, count_is!(4, 0, 13, 13));
        check_cast::<Group<Circuit>, console_root::types::Group<MainnetV0>>(Mode::Private, count_is!(4, 0, 13, 13));
    }

    #[test]
    fn test_field_to_i8() {
        check_cast::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(8, 0, 0, 0));
        check_cast::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 8, 9));
        check_cast::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 8, 9));
    }

    #[test]
    fn test_field_to_i16() {
        check_cast::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Constant, count_is!(16, 0, 0, 0));
        check_cast::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 16, 17));
        check_cast::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 16, 17));
    }

    #[test]
    fn test_field_to_i32() {
        check_cast::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Constant, count_is!(32, 0, 0, 0));
        check_cast::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 32, 33));
        check_cast::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 32, 33));
    }

    #[test]
    fn test_field_to_i64() {
        check_cast::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Constant, count_is!(64, 0, 0, 0));
        check_cast::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 64, 65));
        check_cast::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 64, 65));
    }

    #[test]
    fn test_field_to_i128() {
        check_cast::<I128<Circuit>, console_root::types::I128<MainnetV0>>(Mode::Constant, count_is!(128, 0, 0, 0));
        check_cast::<I128<Circuit>, console_root::types::I128<MainnetV0>>(Mode::Public, count_is!(0, 0, 128, 129));
        check_cast::<I128<Circuit>, console_root::types::I128<MainnetV0>>(Mode::Private, count_is!(0, 0, 128, 129));
    }

    #[test]
    fn test_field_to_scalar() {
        check_cast::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(Mode::Constant, count_is!(253, 0, 0, 0));
        check_cast::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(Mode::Public, count_is!(0, 0, 755, 759));
        check_cast::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(Mode::Private, count_is!(0, 0, 755, 759));
    }

    #[test]
    fn test_field_to_u8() {
        check_cast::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(8, 0, 0, 0));
        check_cast::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 8, 9));
        check_cast::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 8, 9));
    }

    #[test]
    fn test_field_to_u16() {
        check_cast::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Constant, count_is!(16, 0, 0, 0));
        check_cast::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 16, 17));
        check_cast::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 16, 17));
    }

    #[test]
    fn test_field_to_u32() {
        check_cast::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Constant, count_is!(32, 0, 0, 0));
        check_cast::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 32, 33));
        check_cast::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 32, 33));
    }

    #[test]
    fn test_field_to_u64() {
        check_cast::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Constant, count_is!(64, 0, 0, 0));
        check_cast::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 64, 65));
        check_cast::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 64, 65));
    }

    #[test]
    fn test_field_to_u128() {
        check_cast::<U128<Circuit>, console_root::types::U128<MainnetV0>>(Mode::Constant, count_is!(128, 0, 0, 0));
        check_cast::<U128<Circuit>, console_root::types::U128<MainnetV0>>(Mode::Public, count_is!(0, 0, 128, 129));
        check_cast::<U128<Circuit>, console_root::types::U128<MainnetV0>>(Mode::Private, count_is!(0, 0, 128, 129));
    }
}
