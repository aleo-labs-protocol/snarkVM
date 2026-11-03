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
mod zero;

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
    /// The coefficient A / B for the Montgomery curve equation scaled to y^2 == x^3 + (A / B) * x^2 + (1 / B^2) * x.
    pub const MONTGOMERY_A_OVER_B: Field<E> = Field::<E>::new(E::MONTGOMERY_A_OVER_B);
    /// The coefficient B for the Montgomery curve equation.
    pub const MONTGOMERY_B: Field<E> = Field::<E>::new(E::MONTGOMERY_B);
    /// The inverse of the coefficient B for the Montgomery curve equation.
    pub const MONTGOMERY_B_INVERSE: Field<E> = Field::<E>::new(E::MONTGOMERY_B_INVERSE);
    /// The coefficient 1 / B^2 for the Montgomery curve equation scaled to y^2 == x^3 + (A / B) * x^2 + (1 / B^2) * x.
    pub const MONTGOMERY_B_INVERSE_SQUARED: Field<E> = Field::<E>::new(E::MONTGOMERY_B_INVERSE_SQUARED);

    /// Initializes a new group.
    pub fn new(group: E::Affine) -> Self {
        Self { group: group.into() }
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

    #[test]
    fn test_montgomery_derived_constants() {
        let b_inverse = Group::<CurrentEnvironment>::MONTGOMERY_B.inverse().expect("B is nonzero");
        assert_eq!(Group::<CurrentEnvironment>::MONTGOMERY_B_INVERSE, b_inverse);
        assert_eq!(
            Group::<CurrentEnvironment>::MONTGOMERY_A_OVER_B,
            Group::<CurrentEnvironment>::MONTGOMERY_A * b_inverse
        );
        assert_eq!(Group::<CurrentEnvironment>::MONTGOMERY_B_INVERSE_SQUARED, b_inverse.square());
    }
}
