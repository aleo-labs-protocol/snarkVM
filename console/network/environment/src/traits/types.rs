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

use crate::prelude::*;

/// Representation of an address.
pub trait AddressTrait:
    Copy
    + Clone
    + Compare
    + Debug
    + Deref
    + Eq
    + Equal
    + Parser
    + Send
    + SizeInBits
    + SizeInBytes
    + Sync
    + TypeName
    + Visibility
{
}

/// Representation of a boolean.
pub trait BooleanTrait:
    BitAndAssign
    + BitAnd<Self, Output = Self>
    + for<'a> BitAnd<&'a Self, Output = Self>
    + BitOrAssign
    + BitOr<Self, Output = Self>
    + for<'a> BitOr<&'a Self, Output = Self>
    + BitXorAssign
    + BitXor<Self, Output = Self>
    + for<'a> BitXor<&'a Self, Output = Self>
    + Copy
    + Clone
    + Debug
    + Deref
    + Eq
    + Equal
    + Nand
    + Nor
    + Not
    + Parser
    + Send
    + SizeInBits
    + SizeInDataBits
    + SizeInBytes
    + Sync
    + TypeName
    + Uniform
{
}

/// Representation of a base field element.
pub trait FieldTrait:
    'static
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + AddAssign<Self>
    + for<'a> AddAssign<&'a Self>
    + Clone
    + Copy
    + Compare
    + Debug
    + Deref
    + Div<Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Self>
    + DivAssign<Self>
    + for<'a> DivAssign<&'a Self>
    + Double<Output = Self>
    + Eq
    + Equal
    + FromBytes
    + core::hash::Hash
    + Inverse<Output = Self>
    + Mul<Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + MulAssign<Self>
    + for<'a> MulAssign<&'a Self>
    + Neg<Output = Self>
    + One
    + Ord
    + Parser
    + Pow<Self, Output = Self>
    + for<'a> Pow<&'a Self, Output = Self>
    + Product<Self>
    + for<'a> Product<&'a Self>
    + Send
    + SizeInBits
    + SizeInDataBits
    + SizeInBytes
    + Sync
    + Square<Output = Self>
    + SquareRoot<Output = Self>
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + SubAssign<Self>
    + for<'a> SubAssign<&'a Self>
    + Sum<Self>
    + for<'a> Sum<&'a Self>
    + ToBytes
    + TypeName
    + Uniform
    + Zero
{
}

/// Representation of a group element.
pub trait GroupTrait<S: ScalarTrait>:
    'static
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + AddAssign<Self>
    + for<'a> AddAssign<&'a Self>
    + Clone
    + Copy
    + Debug
    + Double<Output = Self>
    + Eq
    + Equal
    + Mul<S>
    + for<'a> Mul<&'a S>
    + MulAssign<S>
    + for<'a> MulAssign<&'a S>
    + Neg<Output = Self>
    + Parser
    + Send
    + SizeInBits
    + SizeInBytes
    + Sync
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + SubAssign<Self>
    + for<'a> SubAssign<&'a Self>
    + Sum<Self>
    + for<'a> Sum<&'a Self>
    + TypeName
    + Uniform
    + Visibility
    + Zero
{
}

/// Representation of a scalar field element.
pub trait ScalarTrait:
    'static
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + AddAssign<Self>
    + for<'a> AddAssign<&'a Self>
    + Clone
    + Copy
    + Compare
    + Debug
    + Deref
    + Div<Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Self>
    + DivAssign<Self>
    + for<'a> DivAssign<&'a Self>
    + Double<Output = Self>
    + Eq
    + Equal
    + Inverse<Output = Self>
    + Mul<Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + MulAssign<Self>
    + for<'a> MulAssign<&'a Self>
    + Neg<Output = Self>
    + One
    + Parser
    + Pow<Self, Output = Self>
    + for<'a> Pow<&'a Self, Output = Self>
    + Product<Self>
    + for<'a> Product<&'a Self>
    + Send
    + SizeInBits
    + SizeInDataBits
    + SizeInBytes
    + Sync
    + Square<Output = Self>
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + SubAssign<Self>
    + for<'a> SubAssign<&'a Self>
    + Sum<Self>
    + for<'a> Sum<&'a Self>
    + TypeName
    + Uniform
    + Zero
{
}

/// Representation of a string.
pub trait StringTrait:
    Clone + Debug + Display + Eq + Equal + FromBytes + Parser + Send + Sync + ToBytes + TypeName + Uniform
{
}

/// Representation of an integer.
pub trait IntegerTrait<I: integer_type::IntegerType, U8: IntegerCore<u8>, U16: IntegerCore<u16>, U32: IntegerCore<u32>>:
    IntegerCore<I>
    + Pow<U8, Output = Self>
    + Shl<U8, Output = Self>
    + for<'a> Shl<&'a U8, Output = Self>
    + ShlChecked<U8, Output = Self>
    + ShlWrapped<U8, Output = Self>
    + ShlAssign<U8>
    + Shr<U8, Output = Self>
    + for<'a> Shr<&'a U8, Output = Self>
    + ShrChecked<U8, Output = Self>
    + ShrWrapped<U8, Output = Self>
    + ShrAssign<U8>
    + Pow<U16, Output = Self>
    + Shl<U16, Output = Self>
    + for<'a> Shl<&'a U16, Output = Self>
    + ShlChecked<U16, Output = Self>
    + ShlWrapped<U16, Output = Self>
    + ShlAssign<U16>
    + Shr<U16, Output = Self>
    + for<'a> Shr<&'a U16, Output = Self>
    + ShrChecked<U16, Output = Self>
    + ShrWrapped<U16, Output = Self>
    + ShrAssign<U16>
    + Pow<U32, Output = Self>
    + Shl<U32, Output = Self>
    + for<'a> Shl<&'a U32, Output = Self>
    + ShlChecked<U32, Output = Self>
    + ShlWrapped<U32, Output = Self>
    + ShlAssign<U32>
    + Shr<U32, Output = Self>
    + for<'a> Shr<&'a U32, Output = Self>
    + ShrChecked<U32, Output = Self>
    + ShrWrapped<U32, Output = Self>
    + ShrAssign<U32>
{
}

pub trait IntegerCore<I: integer_type::IntegerType>:
    'static
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + AddAssign<Self>
    + for<'a> AddAssign<&'a Self>
    + BitAndAssign
    + BitAnd<Self, Output = Self>
    + for<'a> BitAnd<&'a Self, Output = Self>
    + BitOrAssign
    + BitOr<Self, Output = Self>
    + for<'a> BitOr<&'a Self, Output = Self>
    + BitXorAssign
    + BitXor<Self, Output = Self>
    + for<'a> BitXor<&'a Self, Output = Self>
    + Copy
    + Clone
    + Compare
    + Debug
    + Deref
    + Div<Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Self>
    + DivAssign<Self>
    + for<'a> DivAssign<&'a Self>
    + Eq
    + Equal
    + Modulo
    + Mul<Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + MulAssign<Self>
    + for<'a> MulAssign<&'a Self>
    + Neg<Output = Self>
    + Not<Output = Self>
    + One
    + Parser
    + Rem<Self, Output = Self>
    + for<'a> Rem<&'a Self, Output = Self>
    + RemAssign<Self>
    + for<'a> RemAssign<&'a Self>
    + Send
    + SizeInBits
    + SizeInBytes
    + Sync
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + SubAssign<Self>
    + for<'a> SubAssign<&'a Self>
    + TypeName
    + Uniform
    + Visibility
    + Zero
{
}

pub mod integer_type {
    use snarkvm_utilities::{FromBits, FromBytes, ToBits, ToBytes, Uniform};

    use core::{
        fmt::{Debug, Display},
        hash::Hash,
        num::ParseIntError,
        ops::{Div, Rem},
        str::FromStr,
    };
    use num_traits::{
        CheckedNeg,
        CheckedRem,
        CheckedShr,
        One as NumOne,
        PrimInt,
        ToPrimitive,
        WrappingAdd,
        WrappingMul,
        WrappingNeg,
        WrappingShl,
        WrappingShr,
        WrappingSub,
        Zero as NumZero,
    };

    /// Trait bound for integer values. Common to both signed and unsigned integers.
    pub trait IntegerType:
        'static
        + CheckedAbs
        + CheckedNeg
        + CheckedPow
        + CheckedRem
        + CheckedShl
        + CheckedShr
        + CheckedISqrt
        + Debug
        + Default
        + Display
        + FromBits
        + FromBytes
        + FromStr<Err = ParseIntError>
        + Hash
        + Modulo
        + NumZero
        + NumOne
        + PartialOrd
        + Send
        + Sync
        + ToBits
        + ToBytes
        + ToPrimitive
        + Uniform
        + WrappingAbs
        + WrappingAdd
        + WrappingMul
        + WrappingNeg
        + WrappingPow
        + WrappingRem
        + WrappingShl
        + WrappingShr
        + WrappingSub
        + WrappingDiv
        + IntegerProperties
    {
    }

    impl IntegerType for i8 {}
    impl IntegerType for i16 {}
    impl IntegerType for i32 {}
    impl IntegerType for i64 {}
    impl IntegerType for i128 {}

    impl IntegerType for u8 {}
    impl IntegerType for u16 {}
    impl IntegerType for u32 {}
    impl IntegerType for u64 {}
    impl IntegerType for u128 {}

    macro_rules! binary_impl {
        ($trait_name:ident, $t:ty, $method:ident, $arg1: ident, $argname:ident, $arg2: ident, $rt:ty, $body:expr) => {
            impl $trait_name for $t {
                #[inline]
                fn $method(&$arg1, $argname: &$arg2) -> $rt {
                    $body
                }
            }
        };
    }

    pub trait CheckedPow: Sized {
        fn checked_pow(&self, v: &u32) -> Option<Self>;
    }

    binary_impl!(CheckedPow, u8, checked_pow, self, v, u32, Option<u8>, u8::checked_pow(*self, *v));
    binary_impl!(CheckedPow, u16, checked_pow, self, v, u32, Option<u16>, u16::checked_pow(*self, *v));
    binary_impl!(CheckedPow, u32, checked_pow, self, v, u32, Option<u32>, u32::checked_pow(*self, *v));
    binary_impl!(CheckedPow, u64, checked_pow, self, v, u32, Option<u64>, u64::checked_pow(*self, *v));
    binary_impl!(CheckedPow, u128, checked_pow, self, v, u32, Option<u128>, u128::checked_pow(*self, *v));
    binary_impl!(CheckedPow, i8, checked_pow, self, v, u32, Option<i8>, i8::checked_pow(*self, *v));
    binary_impl!(CheckedPow, i16, checked_pow, self, v, u32, Option<i16>, i16::checked_pow(*self, *v));
    binary_impl!(CheckedPow, i32, checked_pow, self, v, u32, Option<i32>, i32::checked_pow(*self, *v));
    binary_impl!(CheckedPow, i64, checked_pow, self, v, u32, Option<i64>, i64::checked_pow(*self, *v));
    binary_impl!(CheckedPow, i128, checked_pow, self, v, u32, Option<i128>, i128::checked_pow(*self, *v));

    pub trait CheckedShl: Sized {
        fn checked_shl(&self, v: &u32) -> Option<Self>;
    }

    #[rustfmt::skip]
    binary_impl!(CheckedShl, u8, checked_shl, self, v, u32, Option<u8>, u8::checked_pow(2u8, *v).and_then(|x| u8::checked_mul(*self, x)));
    #[rustfmt::skip]
    binary_impl!(CheckedShl, u16, checked_shl, self, v, u32, Option<u16>, u16::checked_pow(2u16, *v).and_then(|x| u16::checked_mul(*self, x)));
    #[rustfmt::skip]
    binary_impl!(CheckedShl, u32, checked_shl, self, v, u32, Option<u32>, u32::checked_pow(2u32, *v).and_then(|x| u32::checked_mul(*self, x)));
    #[rustfmt::skip]
    binary_impl!(CheckedShl, u64, checked_shl, self, v, u32, Option<u64>, u64::checked_pow(2u64, *v).and_then(|x| u64::checked_mul(*self, x)));
    #[rustfmt::skip]
    binary_impl!(CheckedShl, u128, checked_shl, self, v, u32, Option<u128>, u128::checked_pow(2u128, *v).and_then(|x| u128::checked_mul(*self, x)));
    #[rustfmt::skip]
    binary_impl!(CheckedShl, i8, checked_shl, self, v, u32, Option<i8>, u8::checked_pow(2u8, *v).and_then(|x| i8::checked_mul(if (x as i8) == i8::MIN { self.wrapping_neg() } else { *self }, x as i8)));
    #[rustfmt::skip]
    binary_impl!(CheckedShl, i16, checked_shl, self, v, u32, Option<i16>, u16::checked_pow(2u16, *v).and_then(|x| i16::checked_mul(if (x as i16) == i16::MIN { self.wrapping_neg() } else { *self }, x as i16)));
    #[rustfmt::skip]
    binary_impl!(CheckedShl, i32, checked_shl, self, v, u32, Option<i32>, u32::checked_pow(2u32, *v).and_then(|x| i32::checked_mul(if (x as i32) == i32::MIN { self.wrapping_neg() } else { *self }, x as i32)));
    #[rustfmt::skip]
    binary_impl!(CheckedShl, i64, checked_shl, self, v, u32, Option<i64>, u64::checked_pow(2u64, *v).and_then(|x| i64::checked_mul(if (x as i64) == i64::MIN { self.wrapping_neg() } else { *self }, x as i64)));
    #[rustfmt::skip]
    binary_impl!(CheckedShl, i128, checked_shl, self, v, u32, Option<i128>, u128::checked_pow(2u128, *v).and_then(|x| i128::checked_mul(if (x as i128) == i128::MIN { self.wrapping_neg() } else { *self }, x as i128)));

    pub trait Modulo: Sized + Rem<Self, Output = Self> {
        fn modulo(&self, v: &Self) -> Self;
    }

    binary_impl!(Modulo, u8, modulo, self, v, Self, u8, u8::wrapping_rem(*self, *v));
    binary_impl!(Modulo, u16, modulo, self, v, Self, u16, u16::wrapping_rem(*self, *v));
    binary_impl!(Modulo, u32, modulo, self, v, Self, u32, u32::wrapping_rem(*self, *v));
    binary_impl!(Modulo, u64, modulo, self, v, Self, u64, u64::wrapping_rem(*self, *v));
    binary_impl!(Modulo, u128, modulo, self, v, Self, u128, u128::wrapping_rem(*self, *v));
    #[rustfmt::skip]
    binary_impl!(Modulo, i8, modulo, self, _v, Self, i8, panic!("modulo is not implemented for i8"));
    #[rustfmt::skip]
    binary_impl!(Modulo, i16, modulo, self, _v, Self, i16, panic!("modulo is not implemented for i16"));
    #[rustfmt::skip]
    binary_impl!(Modulo, i32, modulo, self, _v, Self, i32, panic!("modulo is not implemented for i32"));
    #[rustfmt::skip]
    binary_impl!(Modulo, i64, modulo, self, _v, Self, i64, panic!("modulo is not implemented for i64"));
    #[rustfmt::skip]
    binary_impl!(Modulo, i128, modulo, self, _v, Self, i128, panic!("modulo is not implemented for i128"));

    pub trait WrappingDiv: Sized + Div<Self, Output = Self> {
        fn wrapping_div(&self, v: &Self) -> Self;
    }

    binary_impl!(WrappingDiv, u8, wrapping_div, self, v, Self, u8, u8::wrapping_div(*self, *v));
    binary_impl!(WrappingDiv, u16, wrapping_div, self, v, Self, u16, u16::wrapping_div(*self, *v));
    binary_impl!(WrappingDiv, u32, wrapping_div, self, v, Self, u32, u32::wrapping_div(*self, *v));
    binary_impl!(WrappingDiv, u64, wrapping_div, self, v, Self, u64, u64::wrapping_div(*self, *v));
    binary_impl!(WrappingDiv, u128, wrapping_div, self, v, Self, u128, u128::wrapping_div(*self, *v));
    binary_impl!(WrappingDiv, i8, wrapping_div, self, v, Self, i8, i8::wrapping_div(*self, *v));
    binary_impl!(WrappingDiv, i16, wrapping_div, self, v, Self, i16, i16::wrapping_div(*self, *v));
    binary_impl!(WrappingDiv, i32, wrapping_div, self, v, Self, i32, i32::wrapping_div(*self, *v));
    binary_impl!(WrappingDiv, i64, wrapping_div, self, v, Self, i64, i64::wrapping_div(*self, *v));
    binary_impl!(WrappingDiv, i128, wrapping_div, self, v, Self, i128, i128::wrapping_div(*self, *v));

    pub trait WrappingRem: Sized + Rem<Self, Output = Self> {
        fn wrapping_rem(&self, v: &Self) -> Self;
    }

    binary_impl!(WrappingRem, u8, wrapping_rem, self, v, Self, u8, u8::wrapping_rem(*self, *v));
    binary_impl!(WrappingRem, u16, wrapping_rem, self, v, Self, u16, u16::wrapping_rem(*self, *v));
    binary_impl!(WrappingRem, u32, wrapping_rem, self, v, Self, u32, u32::wrapping_rem(*self, *v));
    binary_impl!(WrappingRem, u64, wrapping_rem, self, v, Self, u64, u64::wrapping_rem(*self, *v));
    binary_impl!(WrappingRem, u128, wrapping_rem, self, v, Self, u128, u128::wrapping_rem(*self, *v));
    binary_impl!(WrappingRem, i8, wrapping_rem, self, v, Self, i8, i8::wrapping_rem(*self, *v));
    binary_impl!(WrappingRem, i16, wrapping_rem, self, v, Self, i16, i16::wrapping_rem(*self, *v));
    binary_impl!(WrappingRem, i32, wrapping_rem, self, v, Self, i32, i32::wrapping_rem(*self, *v));
    binary_impl!(WrappingRem, i64, wrapping_rem, self, v, Self, i64, i64::wrapping_rem(*self, *v));
    binary_impl!(WrappingRem, i128, wrapping_rem, self, v, Self, i128, i128::wrapping_rem(*self, *v));

    pub trait WrappingPow: Sized {
        fn wrapping_pow(&self, v: &u32) -> Self;
    }

    binary_impl!(WrappingPow, u8, wrapping_pow, self, v, u32, u8, u8::wrapping_pow(*self, *v));
    binary_impl!(WrappingPow, u16, wrapping_pow, self, v, u32, u16, u16::wrapping_pow(*self, *v));
    binary_impl!(WrappingPow, u32, wrapping_pow, self, v, u32, u32, u32::wrapping_pow(*self, *v));
    binary_impl!(WrappingPow, u64, wrapping_pow, self, v, u32, u64, u64::wrapping_pow(*self, *v));
    binary_impl!(WrappingPow, u128, wrapping_pow, self, v, u32, u128, u128::wrapping_pow(*self, *v));
    binary_impl!(WrappingPow, i8, wrapping_pow, self, v, u32, i8, i8::wrapping_pow(*self, *v));
    binary_impl!(WrappingPow, i16, wrapping_pow, self, v, u32, i16, i16::wrapping_pow(*self, *v));
    binary_impl!(WrappingPow, i32, wrapping_pow, self, v, u32, i32, i32::wrapping_pow(*self, *v));
    binary_impl!(WrappingPow, i64, wrapping_pow, self, v, u32, i64, i64::wrapping_pow(*self, *v));
    binary_impl!(WrappingPow, i128, wrapping_pow, self, v, u32, i128, i128::wrapping_pow(*self, *v));

    macro_rules! unary_impl {
        ($trait_name:ident, $t:ty, $method:ident, $arg: ident, $rt:ty, $body:expr) => {
            impl $trait_name for $t {
                #[inline]
                fn $method(&$arg) -> $rt {
                    $body
                }
            }
        };
    }

    pub trait CheckedAbs: Sized {
        fn checked_abs(&self) -> Option<Self>;
    }

    unary_impl!(CheckedAbs, u8, checked_abs, self, Option<u8>, Some(*self));
    unary_impl!(CheckedAbs, u16, checked_abs, self, Option<u16>, Some(*self));
    unary_impl!(CheckedAbs, u32, checked_abs, self, Option<u32>, Some(*self));
    unary_impl!(CheckedAbs, u64, checked_abs, self, Option<u64>, Some(*self));
    unary_impl!(CheckedAbs, u128, checked_abs, self, Option<u128>, Some(*self));
    unary_impl!(CheckedAbs, i8, checked_abs, self, Option<i8>, i8::checked_abs(*self));
    unary_impl!(CheckedAbs, i16, checked_abs, self, Option<i16>, i16::checked_abs(*self));
    unary_impl!(CheckedAbs, i32, checked_abs, self, Option<i32>, i32::checked_abs(*self));
    unary_impl!(CheckedAbs, i64, checked_abs, self, Option<i64>, i64::checked_abs(*self));
    unary_impl!(CheckedAbs, i128, checked_abs, self, Option<i128>, i128::checked_abs(*self));

    pub trait WrappingAbs: Sized {
        fn wrapping_abs(&self) -> Self;
    }

    unary_impl!(WrappingAbs, u8, wrapping_abs, self, u8, *self);
    unary_impl!(WrappingAbs, u16, wrapping_abs, self, u16, *self);
    unary_impl!(WrappingAbs, u32, wrapping_abs, self, u32, *self);
    unary_impl!(WrappingAbs, u64, wrapping_abs, self, u64, *self);
    unary_impl!(WrappingAbs, u128, wrapping_abs, self, u128, *self);
    unary_impl!(WrappingAbs, i8, wrapping_abs, self, i8, i8::wrapping_abs(*self));
    unary_impl!(WrappingAbs, i16, wrapping_abs, self, i16, i16::wrapping_abs(*self));
    unary_impl!(WrappingAbs, i32, wrapping_abs, self, i32, i32::wrapping_abs(*self));
    unary_impl!(WrappingAbs, i64, wrapping_abs, self, i64, i64::wrapping_abs(*self));
    unary_impl!(WrappingAbs, i128, wrapping_abs, self, i128, i128::wrapping_abs(*self));

    pub trait CheckedISqrt: Sized {
        fn checked_isqrt(&self) -> Option<Self>;
    }

    unary_impl!(CheckedISqrt, u8, checked_isqrt, self, Option<u8>, Some(u8::isqrt(*self)));
    unary_impl!(CheckedISqrt, u16, checked_isqrt, self, Option<u16>, Some(u16::isqrt(*self)));
    unary_impl!(CheckedISqrt, u32, checked_isqrt, self, Option<u32>, Some(u32::isqrt(*self)));
    unary_impl!(CheckedISqrt, u64, checked_isqrt, self, Option<u64>, Some(u64::isqrt(*self)));
    unary_impl!(CheckedISqrt, u128, checked_isqrt, self, Option<u128>, Some(u128::isqrt(*self)));
    unary_impl!(CheckedISqrt, i8, checked_isqrt, self, Option<i8>, i8::checked_isqrt(*self));
    unary_impl!(CheckedISqrt, i16, checked_isqrt, self, Option<i16>, i16::checked_isqrt(*self));
    unary_impl!(CheckedISqrt, i32, checked_isqrt, self, Option<i32>, i32::checked_isqrt(*self));
    unary_impl!(CheckedISqrt, i64, checked_isqrt, self, Option<i64>, i64::checked_isqrt(*self));
    unary_impl!(CheckedISqrt, i128, checked_isqrt, self, Option<i128>, i128::checked_isqrt(*self));

    /// Properties common to all integer types.
    pub trait IntegerProperties: PrimInt + Debug + Display {
        type Dual: IntegerType;
        /// Returns the number of bits required to represent this integer.
        const BITS: u64;
        /// Returns the maximum value representable by this integer.
        const MAX: Self;
        /// Returns the minimum value representable by this integer.
        const MIN: Self;

        /// Returns `true` if `Self` is a signed integer and `false` otherwise.
        fn is_signed() -> bool;

        /// Returns the name of the integer type as a string slice. (i.e. "u8")
        fn type_name() -> &'static str;

        /// Casts `self` into its dual.
        fn into_dual(self) -> Self::Dual;
    }

    macro_rules! integer_properties_impl {
        ($t:ty, $dual:ty, $is_signed:expr) => {
            impl IntegerProperties for $t {
                type Dual = $dual;

                const BITS: u64 = <$t>::BITS as u64;
                const MAX: $t = <$t>::MAX;
                const MIN: $t = <$t>::MIN;

                #[inline]
                fn is_signed() -> bool {
                    $is_signed
                }

                #[inline]
                fn type_name() -> &'static str {
                    std::any::type_name::<$t>()
                }

                #[inline]
                fn into_dual(self) -> Self::Dual {
                    self as $dual
                }
            }
        };
    }

    integer_properties_impl!(u8, i8, false);
    integer_properties_impl!(u16, i16, false);
    integer_properties_impl!(u32, i32, false);
    integer_properties_impl!(u64, i64, false);
    integer_properties_impl!(u128, i128, false);
    integer_properties_impl!(i8, u8, true);
    integer_properties_impl!(i16, u16, true);
    integer_properties_impl!(i32, u32, true);
    integer_properties_impl!(i64, u64, true);
    integer_properties_impl!(i128, u128, true);
}

/// Trait pattern to prevent abuse of Magnitude.
pub mod integer_magnitude {
    use super::integer_type::IntegerType;
    use num_traits::{ToPrimitive, Unsigned};

    /// Trait for integers that can be used as an unsigned magnitude.
    /// `Magnitude`s are either used to represent an integer exponent
    /// or the right operand in integer shift operations.
    pub trait Magnitude: IntegerType + ToPrimitive + Unsigned {}
    impl Magnitude for u8 {}
    impl Magnitude for u16 {}
    impl Magnitude for u32 {}
}
