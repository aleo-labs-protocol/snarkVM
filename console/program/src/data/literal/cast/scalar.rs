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

impl<E: Environment> Cast<Address<E>> for Scalar<E> {
    /// Casts a `Scalar` to an `Address`.
    ///
    /// This operation converts the scalar to a field element, and then attempts to recover
    /// the group element by treating the field element as an x-coordinate. The group element
    /// is then converted to an address.
    ///
    /// To cast arbitrary scalars to addresses, use `Scalar::cast_lossy`.
    #[inline]
    fn cast(&self) -> Result<Address<E>> {
        let field: Field<E> = self.cast()?;
        Address::from_field(&field)
    }
}

impl<E: Environment> Cast<Boolean<E>> for Scalar<E> {
    /// Casts a `Scalar` to a `Boolean`, if the scalar is zero or one.
    ///
    /// To cast arbitrary scalars to booleans, use `Scalar::cast_lossy`.
    #[inline]
    fn cast(&self) -> Result<Boolean<E>> {
        if self.is_zero() {
            Ok(Boolean::new(false))
        } else if self.is_one() {
            Ok(Boolean::new(true))
        } else {
            bail!("Failed to convert scalar to boolean: scalar is not zero or one")
        }
    }
}

impl<E: Environment> Cast<Group<E>> for Scalar<E> {
    /// Casts a `Scalar` to a `Group`.
    ///
    /// This operation converts the scalar to a field element, and then attempts to recover
    /// the group element by treating the field element as an x-coordinate.
    ///
    /// To cast arbitrary scalars to groups, use `Scalar::cast_lossy`.
    #[inline]
    fn cast(&self) -> Result<Group<E>> {
        let field: Field<E> = self.cast()?;
        Group::from_field(&field)
    }
}

impl<E: Environment> Cast<Field<E>> for Scalar<E> {
    /// Casts a `Scalar` to a `Field`.
    #[inline]
    fn cast(&self) -> Result<Field<E>> {
        self.to_field()
    }
}

impl<E: Environment, I: IntegerType> Cast<Integer<E, I>> for Scalar<E> {
    /// Casts a `Scalar` to an `Integer`, if the scalar is in the range of the integer.
    ///
    /// To cast arbitrary scalars to integers, via truncation, use `Scalar::cast_lossy`.
    #[inline]
    fn cast(&self) -> Result<Integer<E, I>> {
        let bits_le = self.to_bits_le();
        Integer::<E, I>::from_bits_le(&bits_le)
    }
}

impl<E: Environment> Cast<Scalar<E>> for Scalar<E> {
    /// Casts a `Scalar` to a `Scalar`.
    #[inline]
    fn cast(&self) -> Result<Scalar<E>> {
        Ok(*self)
    }
}

impl<E: Environment> Cast<IdentifierLiteral<E>> for Scalar<E> {
    /// Casts a `Scalar` to an `IdentifierLiteral`.
    #[inline]
    fn cast(&self) -> Result<IdentifierLiteral<E>> {
        let field: Field<E> = self.cast()?;
        field.cast()
    }
}
