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

use anyhow::Result;

/// Binary operator for adding two values, enforcing an overflow never occurs.
pub trait AddChecked<Rhs: ?Sized = Self> {
    type Output;

    fn add_checked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for adding two values, wrapping the sum if an overflow occurs.
pub trait AddWrapped<Rhs: ?Sized = Self> {
    type Output;

    fn add_wrapped(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for dividing two values, without checking specific conditions.
pub trait DivUnchecked<Rhs: ?Sized = Self> {
    type Output;

    fn div_unchecked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for dividing two values, enforcing an overflow never occurs.
pub trait DivChecked<Rhs: ?Sized = Self> {
    type Output;

    fn div_checked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for dividing two values, wrapping the quotient if an overflow occurs.
pub trait DivWrapped<Rhs: ?Sized = Self> {
    type Output;

    fn div_wrapped(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for modding two values.
pub trait Modulo<Rhs: ?Sized = Self> {
    type Output;

    fn modulo(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for multiplying two values, enforcing an overflow never occurs.
pub trait MulChecked<Rhs: ?Sized = Self> {
    type Output;

    fn mul_checked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for multiplying two values, wrapping the product if an overflow occurs.
pub trait MulWrapped<Rhs: ?Sized = Self> {
    type Output;

    fn mul_wrapped(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for exponentiating two values, enforcing an overflow never occurs.
pub trait PowChecked<Rhs: ?Sized = Self> {
    type Output;

    fn pow_checked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for exponentiating two values, wrapping the result if an overflow occurs.
pub trait PowWrapped<Rhs: ?Sized = Self> {
    type Output;

    fn pow_wrapped(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for dividing two values and returning the remainder, enforcing an overflow never occurs.
pub trait RemChecked<Rhs: ?Sized = Self> {
    type Output;

    fn rem_checked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for dividing two values, wrapping the remainder if an overflow occurs.
pub trait RemWrapped<Rhs: ?Sized = Self> {
    type Output;

    fn rem_wrapped(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for left shifting a value, checking that the rhs is less than the number
/// of bits in self.
pub trait ShlChecked<Rhs: ?Sized = Self> {
    type Output;

    fn shl_checked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for left shifting a value, safely continuing past the number of bits in self.
pub trait ShlWrapped<Rhs: ?Sized = Self> {
    type Output;

    fn shl_wrapped(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for right shifting a value, checking that the rhs is less than the number
/// of bits in self.
pub trait ShrChecked<Rhs: ?Sized = Self> {
    type Output;

    fn shr_checked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for right shifting a value, safely continuing past the number of bits in self.
pub trait ShrWrapped<Rhs: ?Sized = Self> {
    type Output;

    fn shr_wrapped(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for subtracting two values, enforcing an underflow never occurs.
pub trait SubChecked<Rhs: ?Sized = Self> {
    type Output;

    fn sub_checked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for subtracting two values, wrapping the difference if an underflow occurs.
pub trait SubWrapped<Rhs: ?Sized = Self> {
    type Output;

    fn sub_wrapped(&self, rhs: &Rhs) -> Self::Output;
}

/// Unary operator for retrieving the absolute value, enforcing an overflow never occurs.
pub trait AbsChecked {
    type Output;

    fn abs_checked(self) -> Self::Output;
}

/// Unary operator for retrieving the absolute value, wrapping the result if an overflow occurs.
pub trait AbsWrapped {
    type Output;

    fn abs_wrapped(self) -> Self::Output;
}

/// Unary operator for retrieving the doubled value.
pub trait Double {
    type Output;

    fn double(&self) -> Self::Output;
}

/// Unary operator for retrieving the inverse value.
pub trait Inverse {
    type Output;

    fn inverse(&self) -> Result<Self::Output>;
}

/// Unary operator for retrieving the squared value.
pub trait Square {
    type Output;

    fn square(&self) -> Self::Output;
}

/// Unary operator for retrieving the square root of the value.
pub trait SquareRoot {
    type Output;

    fn square_root(&self) -> Result<Self::Output>;
}
