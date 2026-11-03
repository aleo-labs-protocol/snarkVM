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
    fn cast(&self) -> Result<Address<E>> {
        Address::from_field(self)
    }
}

impl<E: Environment> Cast<Boolean<E>> for Field<E> {
    /// Casts a `Field` to a `Boolean`, if the field is zero or one.
    ///
    /// To cast arbitrary field elements to booleans, use `Field::cast_lossy`.
    #[inline]
    fn cast(&self) -> Result<Boolean<E>> {
        if self.is_zero() {
            Ok(Boolean::new(false))
        } else if self.is_one() {
            Ok(Boolean::new(true))
        } else {
            bail!("Failed to convert field to boolean: field element is not zero or one")
        }
    }
}

impl<E: Environment> Cast<Field<E>> for Field<E> {
    /// Casts a `Field` to a `Field`.
    #[inline]
    fn cast(&self) -> Result<Field<E>> {
        Ok(*self)
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
    fn cast(&self) -> Result<Group<E>> {
        Group::from_field(self)
    }
}

impl<E: Environment, I: IntegerType> Cast<Integer<E, I>> for Field<E> {
    /// Casts a `Field` to an `Integer`, if the field element is in the integer's range.
    ///
    /// To cast arbitrary field elements to integers, use `Field::cast_lossy`.
    #[inline]
    fn cast(&self) -> Result<Integer<E, I>> {
        Integer::from_field(self)
    }
}

impl<E: Environment> Cast<Scalar<E>> for Field<E> {
    /// Casts a `Field` to a `Scalar`, if the field element is in the scalar's range.
    ///
    /// To cast arbitrary field elements to scalars, use `Field::cast_lossy`.
    #[inline]
    fn cast(&self) -> Result<Scalar<E>> {
        Scalar::from_field(self)
    }
}

impl<E: Environment> Cast<IdentifierLiteral<E>> for Field<E> {
    /// Casts a `Field` to an `IdentifierLiteral`.
    #[inline]
    fn cast(&self) -> Result<IdentifierLiteral<E>> {
        IdentifierLiteral::from_field(self)
    }
}
