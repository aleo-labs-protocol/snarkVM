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
mod compare;
mod from_bits;
mod from_field;
mod from_field_lossy;
mod from_fields;
mod one;
mod parse;
mod random;
mod serialize;
mod size_in_bits;
mod size_in_bytes;
mod to_bits;
mod to_field;
mod to_fields;
mod to_scalar;
mod zero;

#[doc(no_inline)]
pub use snarkvm_console_network_environment::prelude::*;
pub use snarkvm_console_types_boolean::Boolean;
pub use snarkvm_console_types_field::Field;
pub use snarkvm_console_types_scalar::Scalar;

use core::marker::PhantomData;

pub type I8<E> = Integer<E, i8>;
pub type I16<E> = Integer<E, i16>;
pub type I32<E> = Integer<E, i32>;
pub type I64<E> = Integer<E, i64>;
pub type I128<E> = Integer<E, i128>;

pub type U8<E> = Integer<E, u8>;
pub type U16<E> = Integer<E, u16>;
pub type U32<E> = Integer<E, u32>;
pub type U64<E> = Integer<E, u64>;
pub type U128<E> = Integer<E, u128>;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Integer<E: Environment, I: IntegerType> {
    /// The underlying integer value.
    integer: I,
    /// PhantomData.
    _phantom: PhantomData<E>,
}

impl<E: Environment, I: IntegerType> IntegerTrait<I, U8<E>, U16<E>, U32<E>> for Integer<E, I> {}

impl<E: Environment, I: IntegerType> IntegerCore<I> for Integer<E, I> {}

impl<E: Environment, I: IntegerType> Visibility for Integer<E, I> {
    type Boolean = Boolean<E>;

    /// Returns the number of field elements to encode `self`.
    fn size_in_fields(&self) -> Result<u16> {
        Ok(1)
    }
}

impl<E: Environment, I: IntegerType> Integer<E, I> {
    pub const MAX: Self = Self::new(I::MAX);
    pub const MIN: Self = Self::new(I::MIN);

    /// Initializes a new integer.
    pub const fn new(integer: I) -> Self {
        Self { integer, _phantom: PhantomData }
    }
}

impl<E: Environment, I: IntegerType> TypeName for Integer<E, I> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        I::type_name()
    }
}

impl<E: Environment, I: IntegerType> Deref for Integer<E, I> {
    type Target = I;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.integer
    }
}
