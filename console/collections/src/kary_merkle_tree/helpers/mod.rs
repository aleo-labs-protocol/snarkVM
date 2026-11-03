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

mod leaf_hash;
pub use leaf_hash::*;

mod path_hash;
pub use path_hash::*;

use snarkvm_console_types::prelude::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BooleanHash<const VARIANT: usize>(pub [bool; VARIANT]);

impl<const VARIANT: usize> BooleanHash<VARIANT> {
    /// Initializes a new "empty" boolean hash.
    pub const fn new() -> Self {
        Self([false; VARIANT])
    }
}

impl<const VARIANT: usize> Default for BooleanHash<VARIANT> {
    /// Initializes a new "empty" boolean hash.
    fn default() -> Self {
        Self::new()
    }
}

impl<const VARIANT: usize> Distribution<BooleanHash<VARIANT>> for StandardUniform {
    /// Returns a random boolean hash.
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BooleanHash<VARIANT> {
        let mut array = [false; VARIANT];
        for entry in array.iter_mut() {
            *entry = rng.random();
        }
        BooleanHash(array)
    }
}

impl<const VARIANT: usize> FromBytes for BooleanHash<VARIANT> {
    /// Reads `self` from `reader` in little-endian order.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the bits.
        let mut array = [false; VARIANT];
        for bit in array.iter_mut() {
            *bit = bool::read_le(&mut reader)?;
        }
        Ok(Self(array))
    }
}

impl<const VARIANT: usize> ToBytes for BooleanHash<VARIANT> {
    /// Writes `self` to `writer` in little-endian order.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.0.as_slice().write_le(&mut writer)
    }
}

impl<const VARIANT: usize> Deref for BooleanHash<VARIANT> {
    type Target = [bool; VARIANT];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
