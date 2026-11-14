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

#![cfg_attr(test, allow(clippy::assertions_on_result_states))]
#![warn(clippy::cast_possible_truncation)]

mod arithmetic;
mod bitwise;
mod bytes;
mod from_bits;
mod from_field;
mod from_fields;
mod from_x_coordinate;
mod from_xy_coordinates;
mod parse;
mod random;
mod serialize;
mod size_in_bits;
mod size_in_bytes;
mod to_bits;
mod to_field;
mod to_fields;
mod to_x_coordinate;
mod to_xy_coordinates;
mod to_y_coordinate;
mod window_table;
mod zero;

pub use window_table::GroupWindowTable;

pub use snarkvm_console_network_environment::prelude::*;
pub use snarkvm_console_types_boolean::Boolean;
pub use snarkvm_console_types_field::Field;
pub use snarkvm_console_types_scalar::Scalar;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Group<E: Environment> {
    /// The underlying group element.
    group: E::Projective,
}

impl<E: Environment> GroupTrait<Scalar<E>> for Group<E> {}

impl<E: Environment> Visibility for Group<E> {
    type Boolean = Boolean<E>;

    /// Returns the number of field elements to encode `self`.
    fn size_in_fields(&self) -> Result<u16> {
        Ok(1)
    }
}

impl<E: Environment> Group<E> {
    /// The coefficient A for the twisted Edwards curve equation.
    pub const EDWARDS_A: Field<E> = Field::<E>::new(E::EDWARDS_A);
    /// The coefficient D for the twisted Edwards curve equation.
    pub const EDWARDS_D: Field<E> = Field::<E>::new(E::EDWARDS_D);
    /// The coefficient A for the Montgomery curve equation.
    pub const MONTGOMERY_A: Field<E> = Field::<E>::new(E::MONTGOMERY_A);
    /// The coefficient B for the Montgomery curve equation.
    pub const MONTGOMERY_B: Field<E> = Field::<E>::new(E::MONTGOMERY_B);

    /// Initializes a new group without checking that `group` is a group element.
    #[deprecated(
        since = "4.13.0",
        note = "use `Group::try_new`, which rejects invalid points; `from_xy_coordinates_unchecked` skips the check"
    )]
    pub fn new(group: E::Affine) -> Self {
        Self::new_unchecked(group)
    }

    /// Initializes a new group, if `group` is on the curve and in the prime-order subgroup.
    pub fn try_new(group: E::Affine) -> Result<Self> {
        // The subgroup check reads the Edwards `t` coordinate, which a caller can set to any value.
        let group = E::Affine::from_coordinates_unchecked((group.to_x_coordinate(), group.to_y_coordinate()));
        ensure!(group.is_on_curve(), "Group element is not on the curve");
        ensure!(group.is_in_correct_subgroup_assuming_on_curve(), "Group element is not in the prime-order subgroup");
        Ok(Self::new_unchecked(group))
    }

    /// Returns `self` with its projective `z` coordinate set to one, which makes `to_affine` skip an inversion.
    pub fn normalized(&self) -> Self {
        Self::new_unchecked(self.group.to_affine())
    }

    /// Returns the prime subgroup generator.
    pub fn generator() -> Self {
        Self { group: E::Affine::prime_subgroup_generator().to_projective() }
    }

    /// Returns `self * COFACTOR`.
    pub fn mul_by_cofactor(&self) -> Self {
        // (For advanced users) The cofactor for this curve is `4`. Thus doubling is used to be performant.
        // See unit tests below, which sanity check that this condition holds.
        debug_assert!(E::Affine::cofactor().len() == 1 && E::Affine::cofactor()[0] == 4);

        Self { group: self.group.double().double() }
    }

    /// Returns `self / COFACTOR`.
    pub fn div_by_cofactor(&self) -> Self {
        Self { group: self.group.to_affine().mul_by_cofactor_inv().into() }
    }
}

impl<E: Environment> Group<E> {
    /// This internal function initializes a group element from affine coordinates, without checking them.
    fn new_unchecked(group: E::Affine) -> Self {
        Self { group: group.into() }
    }

    /// This internal function initializes a group element from projective coordinates.
    const fn from_projective(group: E::Projective) -> Self {
        Self { group }
    }
}

impl<E: Environment> TypeName for Group<E> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "group"
    }
}

impl<E: Environment> Deref for Group<E> {
    type Target = E::Projective;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.group
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;
    type Affine = <CurrentEnvironment as Environment>::Affine;
    type BaseField = <CurrentEnvironment as Environment>::Field;

    const ITERATIONS: usize = 100;

    #[test]
    fn test_try_new_accepts_group_elements() {
        let mut rng = TestRng::default();

        for element in [Group::<CurrentEnvironment>::zero(), Group::generator()] {
            assert_eq!(element, Group::try_new(element.to_affine()).unwrap());
        }
        for _ in 0..ITERATIONS {
            let element = Group::<CurrentEnvironment>::rand(&mut rng);
            assert_eq!(element, Group::try_new(element.to_affine()).unwrap());
        }
    }

    #[test]
    fn test_try_new_rejects_points_off_the_curve() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let point = Affine::from_coordinates_unchecked((BaseField::rand(&mut rng), BaseField::rand(&mut rng)));
            assert!(!point.is_on_curve());
            assert!(Group::<CurrentEnvironment>::try_new(point).is_err());
        }
    }

    #[test]
    fn test_try_new_rejects_points_outside_the_subgroup() {
        let mut rng = TestRng::default();

        // The point of order two.
        let order_two = Affine::from_coordinates_unchecked((BaseField::zero(), -BaseField::one()));
        assert!(order_two.is_on_curve());
        assert!(Group::<CurrentEnvironment>::try_new(order_two).is_err());

        // A group element plus the point of order two.
        for _ in 0..ITERATIONS {
            let element = Group::<CurrentEnvironment>::rand(&mut rng);
            let point = element.add_mixed(&order_two).to_affine();
            assert!(point.is_on_curve());
            assert!(Group::<CurrentEnvironment>::try_new(point).is_err());
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_try_new_ignores_a_forged_t() {
        let mut rng = TestRng::default();

        let order_two = Affine::from_coordinates_unchecked((BaseField::zero(), -BaseField::one()));
        for _ in 0..ITERATIONS {
            let element = Group::<CurrentEnvironment>::rand(&mut rng);
            let point = element.to_affine();
            let forged = Affine::new(point.to_x_coordinate(), point.to_y_coordinate(), BaseField::rand(&mut rng));
            assert_eq!(element, Group::try_new(forged).unwrap());

            let point = element.add_mixed(&order_two).to_affine();
            let forged = Affine::new(point.to_x_coordinate(), point.to_y_coordinate(), BaseField::rand(&mut rng));
            assert!(Group::<CurrentEnvironment>::try_new(forged).is_err());
        }
    }

    #[test]
    fn test_normalized_is_the_same_element() {
        let mut rng = TestRng::default();

        assert_eq!(Group::<CurrentEnvironment>::zero(), Group::<CurrentEnvironment>::zero().normalized());
        for _ in 0..ITERATIONS {
            // The double has a projective `z` coordinate other than one.
            let element = Group::<CurrentEnvironment>::rand(&mut rng).double();
            assert_eq!(element, element.normalized());
            assert_eq!(element.to_affine(), element.normalized().to_affine());
            assert!(!element.is_normalized());
            assert!(element.normalized().is_normalized());
        }
    }
}
