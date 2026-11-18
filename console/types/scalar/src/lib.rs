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
mod one;
mod parse;
mod random;
mod serialize;
mod size_in_bits;
mod size_in_bytes;
mod to_bits;
mod to_field;
mod zero;

#[doc(no_inline)]
pub use snarkvm_console_network_environment::prelude::*;
pub use snarkvm_console_types_boolean::Boolean;
pub use snarkvm_console_types_field::Field;

use zeroize::Zeroize;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Zeroize)]
pub struct Scalar<E: Environment> {
    /// The underlying scalar element.
    scalar: E::Scalar,
}

impl<E: Environment> ScalarTrait for Scalar<E> {}

impl<E: Environment> Scalar<E> {
    /// The scalar size in bits.
    pub const SIZE_IN_BITS: usize = E::Scalar::SIZE_IN_BITS;
    /// The scalar size in bytes.
    pub const SIZE_IN_BYTES: usize = E::Scalar::SIZE_IN_BITS.div_ceil(8);
    /// The scalar capacity for data bits.
    pub const SIZE_IN_DATA_BITS: usize = E::Scalar::SIZE_IN_DATA_BITS;

    /// Initializes a new scalar.
    pub const fn new(scalar: E::Scalar) -> Self {
        Self { scalar }
    }
}

impl<E: Environment> TypeName for Scalar<E> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "scalar"
    }
}

impl<E: Environment> Deref for Scalar<E> {
    type Target = E::Scalar;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.scalar
    }
}
