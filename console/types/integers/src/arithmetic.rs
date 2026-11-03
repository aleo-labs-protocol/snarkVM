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

impl<E: Environment, I: IntegerType> Neg for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `negation` of `self`.
    #[inline]
    fn neg(self) -> Self::Output {
        match I::is_signed() {
            true => match self.integer.checked_neg() {
                Some(integer) => Integer::new(integer),
                None => E::halt(format!("Integer negation failed on: {}", self.integer)),
            },
            false => E::halt("Negation of unsigned integers is not supported."),
        }
    }
}

impl<E: Environment, I: IntegerType> AbsChecked for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `absolute value` of `self`.
    #[inline]
    fn abs_checked(self) -> Self::Output {
        match I::is_signed() {
            true => match self.integer.checked_abs() {
                Some(integer) => Integer::new(integer),
                None => E::halt(format!("Integer absolute value failed on: {}", self.integer)),
            },
            false => self,
        }
    }
}

impl<E: Environment, I: IntegerType> AbsWrapped for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `absolute value` of `self`.
    #[inline]
    fn abs_wrapped(self) -> Self::Output {
        match I::is_signed() {
            true => Integer::new(self.integer.wrapping_abs()),
            false => self,
        }
    }
}

impl<E: Environment, I: IntegerType> Add<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `sum` of `self` and `other`.
    #[inline]
    fn add(self, other: Integer<E, I>) -> Self::Output {
        match self.integer.checked_add(&other.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer addition failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> Add<&Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `sum` of `self` and `other`.
    #[inline]
    fn add(self, other: &Integer<E, I>) -> Self::Output {
        match self.integer.checked_add(&other.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer addition failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> AddWrapped<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `sum` of `self` and `other`.
    #[inline]
    fn add_wrapped(&self, other: &Integer<E, I>) -> Self::Output {
        Integer::new(self.integer.wrapping_add(&other.integer))
    }
}

impl<E: Environment, I: IntegerType> AddAssign<Integer<E, I>> for Integer<E, I> {
    /// Adds `other` to `self`.
    #[inline]
    fn add_assign(&mut self, other: Integer<E, I>) {
        match self.integer.checked_add(&other.integer) {
            Some(integer) => self.integer = integer,
            None => E::halt(format!("Integer addition failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> AddAssign<&Integer<E, I>> for Integer<E, I> {
    /// Adds `other` to `self`.
    #[inline]
    fn add_assign(&mut self, other: &Integer<E, I>) {
        match self.integer.checked_add(&other.integer) {
            Some(integer) => self.integer = integer,
            None => E::halt(format!("Integer addition failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> Sub<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `difference` of `self` and `other`.
    #[inline]
    fn sub(self, other: Integer<E, I>) -> Self::Output {
        match self.integer.checked_sub(&other.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer subtraction failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> Sub<&Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `difference` of `self` and `other`.
    #[inline]
    fn sub(self, other: &Integer<E, I>) -> Self::Output {
        match self.integer.checked_sub(&other.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer subtraction failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> SubWrapped<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `difference` of `self` and `other`.
    #[inline]
    fn sub_wrapped(&self, other: &Integer<E, I>) -> Self::Output {
        Integer::new(self.integer.wrapping_sub(&other.integer))
    }
}

impl<E: Environment, I: IntegerType> SubAssign<Integer<E, I>> for Integer<E, I> {
    /// Subtracts `other` from `self`.
    #[inline]
    fn sub_assign(&mut self, other: Integer<E, I>) {
        match self.integer.checked_sub(&other.integer) {
            Some(integer) => self.integer = integer,
            None => E::halt(format!("Integer subtraction failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> SubAssign<&Integer<E, I>> for Integer<E, I> {
    /// Subtracts `other` from `self`.
    #[inline]
    fn sub_assign(&mut self, other: &Integer<E, I>) {
        match self.integer.checked_sub(&other.integer) {
            Some(integer) => self.integer = integer,
            None => E::halt(format!("Integer subtraction failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> Mul<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `product` of `self` and `other`.
    #[inline]
    fn mul(self, other: Integer<E, I>) -> Self::Output {
        match self.integer.checked_mul(&other.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer multiplication failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> Mul<&Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `product` of `self` and `other`.
    #[inline]
    fn mul(self, other: &Integer<E, I>) -> Self::Output {
        match self.integer.checked_mul(&other.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer multiplication failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> MulWrapped<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `product` of `self` and `other`.
    #[inline]
    fn mul_wrapped(&self, other: &Integer<E, I>) -> Self::Output {
        Integer::new(self.integer.wrapping_mul(&other.integer))
    }
}

impl<E: Environment, I: IntegerType> MulAssign<Integer<E, I>> for Integer<E, I> {
    /// Multiplies `self` by `other`.
    #[inline]
    fn mul_assign(&mut self, other: Integer<E, I>) {
        match self.integer.checked_mul(&other.integer) {
            Some(integer) => self.integer = integer,
            None => E::halt(format!("Integer multiplication failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> MulAssign<&Integer<E, I>> for Integer<E, I> {
    /// Multiplies `self` by `other`.
    #[inline]
    fn mul_assign(&mut self, other: &Integer<E, I>) {
        match self.integer.checked_mul(&other.integer) {
            Some(integer) => self.integer = integer,
            None => E::halt(format!("Integer multiplication failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> Div<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `quotient` of `self` and `other`.
    #[inline]
    fn div(self, other: Integer<E, I>) -> Self::Output {
        match self.integer.checked_div(&other.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer division failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> Div<&Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `quotient` of `self` and `other`.
    #[inline]
    fn div(self, other: &Integer<E, I>) -> Self::Output {
        match self.integer.checked_div(&other.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer division failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> DivWrapped<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `quotient` of `self` and `other`.
    #[inline]
    fn div_wrapped(&self, other: &Integer<E, I>) -> Self::Output {
        match other.is_zero() {
            true => E::halt(format!("Integer division by zero: {self} / {other}")),
            false => Integer::new(self.integer.wrapping_div(&other.integer)),
        }
    }
}

impl<E: Environment, I: IntegerType> DivAssign<Integer<E, I>> for Integer<E, I> {
    /// Divides `self` by `other`.
    #[inline]
    fn div_assign(&mut self, other: Integer<E, I>) {
        match self.integer.checked_div(&other.integer) {
            Some(integer) => self.integer = integer,
            None => E::halt(format!("Integer division failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> DivAssign<&Integer<E, I>> for Integer<E, I> {
    /// Divides `self` by `other`.
    #[inline]
    fn div_assign(&mut self, other: &Integer<E, I>) {
        match self.integer.checked_div(&other.integer) {
            Some(integer) => self.integer = integer,
            None => E::halt(format!("Integer division failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> Modulo<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the result of taking the modulus of `self` with respect to `other`.
    #[inline]
    fn modulo(&self, other: &Integer<E, I>) -> Self {
        match I::is_signed() {
            true => E::halt("Taking the modulus of signed integers is not supported"),
            false => match other.is_zero() {
                true => E::halt(format!("Integer modulus by zero: {self} % {other}")),
                false => Integer::new(self.integer.modulo(&other.integer)),
            },
        }
    }
}

impl<E: Environment, I: IntegerType> Rem<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `remainder` of `self` divided by `other`.
    #[inline]
    fn rem(self, other: Integer<E, I>) -> Self {
        match self.integer.checked_rem(&other.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer remainder failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> Rem<&Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `remainder` of `self` divided by `other`.
    #[inline]
    fn rem(self, other: &Integer<E, I>) -> Self {
        match self.integer.checked_rem(&other.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer remainder failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> RemWrapped<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `remainder` of `self` divided by `other`.
    #[inline]
    fn rem_wrapped(&self, other: &Integer<E, I>) -> Self::Output {
        match other.is_zero() {
            true => E::halt(format!("Integer remainder by zero: {self} % {other}")),
            false => Integer::new(self.integer.wrapping_rem(&other.integer)),
        }
    }
}

impl<E: Environment, I: IntegerType> RemAssign<Integer<E, I>> for Integer<E, I> {
    /// Returns the `remainder` of `self` divided by `other`.
    #[inline]
    fn rem_assign(&mut self, other: Integer<E, I>) {
        match self.integer.checked_rem(&other.integer) {
            Some(integer) => self.integer = integer,
            None => E::halt(format!("Integer remainder failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType> RemAssign<&Integer<E, I>> for Integer<E, I> {
    /// Returns the `remainder` of `self` divided by `other`.
    #[inline]
    fn rem_assign(&mut self, other: &Integer<E, I>) {
        match self.integer.checked_rem(&other.integer) {
            Some(integer) => self.integer = integer,
            None => E::halt(format!("Integer remainder failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Pow<Integer<E, M>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `power` of `self` to the power of `other`.
    #[inline]
    fn pow(self, other: Integer<E, M>) -> Self::Output {
        match self.integer.checked_pow(&other.integer.to_u32().unwrap()) {
            // Unwrap is safe as we only cast up.
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer power failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Pow<&Integer<E, M>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `power` of `self` to the power of `other`.
    #[inline]
    fn pow(self, other: &Integer<E, M>) -> Self::Output {
        match self.integer.checked_pow(&other.integer.to_u32().unwrap()) {
            // Unwrap is safe as we only cast up.
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer power failed on: {self} and {other}")),
        }
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> PowWrapped<Integer<E, M>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `power` of `self` to the power of `other`.
    #[inline]
    fn pow_wrapped(&self, other: &Integer<E, M>) -> Self::Output {
        Integer::new(self.integer.wrapping_pow(&other.integer.to_u32().unwrap()))
    }
}

impl<E: Environment, I: IntegerType> Square for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `square` of `self`.
    #[inline]
    fn square(&self) -> Self::Output {
        match self.integer.checked_mul(&self.integer) {
            Some(integer) => Integer::new(integer),
            None => E::halt(format!("Integer square failed on: {}", self.integer)),
        }
    }
}

impl<E: Environment, I: IntegerType> SquareRoot for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `square_root` of `self`.
    #[inline]
    fn square_root(&self) -> Result<Self::Output> {
        match self.integer.checked_isqrt() {
            Some(integer) => Ok(Integer::new(integer)),
            None => bail!("Integer square failed on: {self}"),
        }
    }
}
