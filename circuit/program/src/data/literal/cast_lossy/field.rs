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

impl<E: Environment> CastLossy<Address<E>> for Field<E> {
    /// Casts a `Field` to an `Address`.
    ///
    /// This operation attempts to recover the group element from the given field,
    /// which is then used to construct the address. See the documentation of `Field::cast_lossy`
    /// on the `Group` type for more details.
    #[inline]
    fn cast_lossy(&self) -> Address<E> {
        // Perform a lossy cast to a group element.
        let group: Group<E> = self.cast_lossy();
        // Convert the group element to an address.
        Address::from_group(group)
    }
}

impl<E: Environment> CastLossy<Boolean<E>> for Field<E> {
    /// Casts a `Field` to a `Boolean`, with lossy truncation.
    /// This operation returns the least significant bit of the field.
    #[inline]
    fn cast_lossy(&self) -> Boolean<E> {
        let bits_le = self.to_bits_le();
        debug_assert!(!bits_le.is_empty(), "An integer must have at least one bit");
        bits_le[0].clone()
    }
}

impl<E: Environment> CastLossy<Field<E>> for Field<E> {
    /// Casts a `Field` to a `Field`.
    /// This is an identity cast, so it is **always** lossless.
    #[inline]
    fn cast_lossy(&self) -> Field<E> {
        self.clone()
    }
}

impl<E: Environment> CastLossy<Group<E>> for Field<E> {
    /// Casts a `Field` to a `Group`.
    ///
    /// This operation attempts to recover the group element from the given field.
    ///
    /// If the field is a valid x-coordinate, then the group element is returned.
    /// If the field is not a valid x-coordinate, then if the field is the one element,
    /// the generator of the prime-order subgroup is returned.
    /// Otherwise, Elligator-2 is applied to the field element to recover a group element.
    #[inline]
    fn cast_lossy(&self) -> Group<E> {
        // This method requires that an `x-coordinate` of 1 is an invalid group element.
        // This is used by the ternary below, which uses 'is_x_one' to determine whether to return the generator.
        debug_assert!(console::Group::from_x_coordinate(<console::Field<E::Network> as console::One>::one()).is_err());

        // Attempt to find a group element with self as the x-coordinate.
        let (point_with_x, x_is_not_in_group) = Group::from_x_coordinate_flagged(self.clone());

        // Determine if the field element is zero.
        let is_x_zero = self.is_zero();
        // Determine if the field element is one.
        let is_x_one = self.is_one();

        // Initialize the group generator.
        let generator = Group::generator();

        // Determine the input to Elligator-2, based on the x-coordinate.
        // If self is 0, we pass 1 to Elligator-2 instead.
        // Note that, in this case, we won't use the result of Elligator-2,
        // because the point (0, 1) is in the subgroup, and that is what we return.
        let elligator_input = Field::ternary(&is_x_zero, &Field::one(), self);
        // Perform Elligator-2 on the field element, to recover a group element.
        let elligator_point = Elligator2::encode(&elligator_input);

        // Select either the generator or the result of Elligator-2, depending on whether x is 1 or not.
        // This is only used when x is not in the group, see below.
        let generator_or_elligator_point = Group::ternary(&is_x_one, &generator, &elligator_point);

        // Select either the group point with x or the generator or the result of Elligator-2,
        // depending on whether x is in the group or not, and, if it is not, based on whether it is 1 or not.
        Group::ternary(&x_is_not_in_group, &generator_or_elligator_point, &point_with_x)
    }
}

impl<E: Environment, I: IntegerType> CastLossy<Integer<E, I>> for Field<E> {
    /// Casts a `Field` to an `Integer`, with lossy truncation.
    /// This operation truncates the field to an integer.
    #[inline]
    fn cast_lossy(&self) -> Integer<E, I> {
        Integer::from_field_lossy(self)
    }
}

impl<E: Environment> CastLossy<Scalar<E>> for Field<E> {
    /// Casts a `Field` to a `Scalar`, with lossy truncation.
    /// This operation truncates the field to a scalar.
    #[inline]
    fn cast_lossy(&self) -> Scalar<E> {
        Scalar::from_field_lossy(self)
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
    ) -> (console_root::types::Field<MainnetV0>, Field<Circuit>) {
        let console_value = match i {
            0 => console_root::types::Field::<MainnetV0>::zero(),
            1 => console_root::types::Field::<MainnetV0>::one(),
            _ => Uniform::rand(rng),
        };
        let circuit_value = Field::<Circuit>::new(mode, console_value);
        (console_value, circuit_value)
    }

    check_cast_lossy!(cast_lossy, Field<Circuit>, console_root::types::Field::<MainnetV0>);

    #[test]
    fn test_field_to_address() {
        check_cast_lossy_by_value::<Address<Circuit>, console_root::types::Address<MainnetV0>>(
            Mode::Constant,
            constant_cast_to_group_count,
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
    fn test_field_to_boolean() {
        check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
            Mode::Constant,
            count_is!(253, 0, 0, 0),
        );
        check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
            Mode::Public,
            count_is!(0, 0, 505, 507),
        );
        check_cast_lossy::<Boolean<Circuit>, console_root::types::Boolean<MainnetV0>>(
            Mode::Private,
            count_is!(0, 0, 505, 507),
        );
    }

    #[test]
    fn test_field_to_field() {
        check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(
            Mode::Constant,
            count_is!(0, 0, 0, 0),
        );
        check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Public, count_is!(0, 0, 0, 0));
        check_cast_lossy::<Field<Circuit>, console_root::types::Field<MainnetV0>>(Mode::Private, count_is!(0, 0, 0, 0));
    }

    #[test]
    fn test_field_to_group() {
        check_cast_lossy_by_value::<Group<Circuit>, console_root::types::Group<MainnetV0>>(
            Mode::Constant,
            constant_cast_to_group_count,
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
    fn test_field_to_i8() {
        check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Constant, count_is!(253, 0, 0, 0));
        check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Public, count_is!(0, 0, 505, 507));
        check_cast_lossy::<I8<Circuit>, console_root::types::I8<MainnetV0>>(Mode::Private, count_is!(0, 0, 505, 507));
    }

    #[test]
    fn test_field_to_i16() {
        check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Constant, count_is!(253, 0, 0, 0));
        check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Public, count_is!(0, 0, 505, 507));
        check_cast_lossy::<I16<Circuit>, console_root::types::I16<MainnetV0>>(Mode::Private, count_is!(0, 0, 505, 507));
    }

    #[test]
    fn test_field_to_i32() {
        check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Constant, count_is!(253, 0, 0, 0));
        check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Public, count_is!(0, 0, 505, 507));
        check_cast_lossy::<I32<Circuit>, console_root::types::I32<MainnetV0>>(Mode::Private, count_is!(0, 0, 505, 507));
    }

    #[test]
    fn test_field_to_i64() {
        check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Constant, count_is!(253, 0, 0, 0));
        check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Public, count_is!(0, 0, 505, 507));
        check_cast_lossy::<I64<Circuit>, console_root::types::I64<MainnetV0>>(Mode::Private, count_is!(0, 0, 505, 507));
    }

    #[test]
    fn test_field_to_i128() {
        check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
            Mode::Constant,
            count_is!(253, 0, 0, 0),
        );
        check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
            Mode::Public,
            count_is!(0, 0, 505, 507),
        );
        check_cast_lossy::<I128<Circuit>, console_root::types::I128<MainnetV0>>(
            Mode::Private,
            count_is!(0, 0, 505, 507),
        );
    }

    #[test]
    fn test_field_to_scalar() {
        check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
            Mode::Constant,
            count_is!(253, 0, 0, 0),
        );
        check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
            Mode::Public,
            count_is!(0, 0, 505, 507),
        );
        check_cast_lossy::<Scalar<Circuit>, console_root::types::Scalar<MainnetV0>>(
            Mode::Private,
            count_is!(0, 0, 505, 507),
        );
    }

    #[test]
    fn test_field_to_u8() {
        check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Constant, count_is!(253, 0, 0, 0));
        check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Public, count_is!(0, 0, 505, 507));
        check_cast_lossy::<U8<Circuit>, console_root::types::U8<MainnetV0>>(Mode::Private, count_is!(0, 0, 505, 507));
    }

    #[test]
    fn test_field_to_u16() {
        check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Constant, count_is!(253, 0, 0, 0));
        check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Public, count_is!(0, 0, 505, 507));
        check_cast_lossy::<U16<Circuit>, console_root::types::U16<MainnetV0>>(Mode::Private, count_is!(0, 0, 505, 507));
    }

    #[test]
    fn test_field_to_u32() {
        check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Constant, count_is!(253, 0, 0, 0));
        check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Public, count_is!(0, 0, 505, 507));
        check_cast_lossy::<U32<Circuit>, console_root::types::U32<MainnetV0>>(Mode::Private, count_is!(0, 0, 505, 507));
    }

    #[test]
    fn test_field_to_u64() {
        check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Constant, count_is!(253, 0, 0, 0));
        check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Public, count_is!(0, 0, 505, 507));
        check_cast_lossy::<U64<Circuit>, console_root::types::U64<MainnetV0>>(Mode::Private, count_is!(0, 0, 505, 507));
    }

    #[test]
    fn test_field_to_u128() {
        check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
            Mode::Constant,
            count_is!(253, 0, 0, 0),
        );
        check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
            Mode::Public,
            count_is!(0, 0, 505, 507),
        );
        check_cast_lossy::<U128<Circuit>, console_root::types::U128<MainnetV0>>(
            Mode::Private,
            count_is!(0, 0, 505, 507),
        );
    }
}
