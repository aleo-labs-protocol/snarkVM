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

mod bitwise;
mod bytes;
mod from_bits;
mod parse;
mod random;
mod serialize;
mod size_in_bits;
mod size_in_bytes;
mod to_bits;

#[doc(no_inline)]
pub use snarkvm_console_network_environment::prelude::*;

use core::marker::PhantomData;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Boolean<E: Environment> {
    /// The underlying boolean.
    boolean: bool,
    /// PhantomData.
    _phantom: PhantomData<E>,
}

impl<E: Environment> BooleanTrait for Boolean<E> {}

impl<E: Environment> Boolean<E> {
    /// Initializes a new boolean.
    pub const fn new(boolean: bool) -> Self {
        Self { boolean, _phantom: PhantomData }
    }

    /// Initializes a `false` boolean.
    #[deprecated(since = "0.1.0", note = "This is used for **testing** purposes")]
    pub const fn zero() -> Self {
        Self::new(false)
    }
}

impl<E: Environment> TypeName for Boolean<E> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "boolean"
    }
}

impl<E: Environment> Deref for Boolean<E> {
    type Target = bool;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.boolean
    }
}

impl<E: Environment> PartialEq<Boolean<E>> for bool {
    fn eq(&self, other: &Boolean<E>) -> bool {
        *self == **other
    }
}
