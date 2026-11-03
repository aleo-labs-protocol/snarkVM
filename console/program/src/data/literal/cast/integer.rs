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

impl<E: Environment, I: IntegerType> Cast<Address<E>> for Integer<E, I> {
    /// Casts an `Integer` to an `Address`.
    ///
    /// This operation converts the integer to a field element, and then attempts to recover
    /// the group element by treating the field element as an x-coordinate. The group element
    /// is then converted to an address.
    ///
    /// To cast arbitrary integers to addresses, use `Integer::cast_lossy`.
    #[inline]
    fn cast(&self) -> Result<Address<E>> {
        let field: Field<E> = self.cast()?;
        field.cast()
    }
}

impl<E: Environment, I: IntegerType> Cast<Boolean<E>> for Integer<E, I> {
    /// Casts an `Integer` to a `Boolean`, if the integer is zero or one.
    ///
    /// To cast arbitrary integers to booleans, use `Integer::cast_lossy`.
    #[inline]
    fn cast(&self) -> Result<Boolean<E>> {
        if self.is_zero() {
            Ok(Boolean::new(false))
        } else if self.is_one() {
            Ok(Boolean::new(true))
        } else {
            bail!("Failed to convert integer to boolean: integer is not zero or one")
        }
    }
}

impl<E: Environment, I: IntegerType> Cast<Field<E>> for Integer<E, I> {
    /// Casts an `Integer` to a `Field`.
    #[inline]
    fn cast(&self) -> Result<Field<E>> {
        self.to_field()
    }
}

impl<E: Environment, I: IntegerType> Cast<Group<E>> for Integer<E, I> {
    /// Casts an `Integer` to a `Group`.
    ///
    /// This operation converts the integer to a field element, and then attempts to recover
    /// the group element by treating the field element as an x-coordinate.
    ///
    /// To cast arbitrary integers to groups, use `Integer::cast_lossy`.
    #[inline]
    fn cast(&self) -> Result<Group<E>> {
        let field: Field<E> = self.cast()?;
        field.cast()
    }
}

impl<E: Environment, I0: IntegerType, I1: IntegerType + TryFrom<I0>> Cast<Integer<E, I1>> for Integer<E, I0> {
    /// Casts an `Integer` to another `Integer`, if the conversion is lossless.
    #[inline]
    fn cast(&self) -> Result<Integer<E, I1>> {
        Ok(Integer::<E, I1>::new(match I1::try_from(**self) {
            Ok(value) => value,
            Err(_) => bail!("Failed to convert '{}' into '{}'", I0::type_name(), I1::type_name()),
        }))
    }
}

impl<E: Environment, I: IntegerType> Cast<Scalar<E>> for Integer<E, I> {
    /// Casts an `Integer` to a `Scalar`.
    #[inline]
    fn cast(&self) -> Result<Scalar<E>> {
        let bits_le = self.to_bits_le();
        Scalar::<E>::from_bits_le(&bits_le)
    }
}

impl<E: Environment, I: IntegerType> Cast<IdentifierLiteral<E>> for Integer<E, I> {
    /// Casts an `Integer` to an `IdentifierLiteral`.
    #[inline]
    fn cast(&self) -> Result<IdentifierLiteral<E>> {
        let field: Field<E> = self.cast()?;
        field.cast()
    }
}
