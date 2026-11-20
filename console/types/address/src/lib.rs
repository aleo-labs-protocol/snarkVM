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
mod from_field;
mod from_fields;
mod parse;
mod random;
mod serialize;
mod size_in_bits;
mod size_in_bytes;
mod to_bits;
mod to_field;
mod to_fields;
mod to_group;

#[doc(no_inline)]
pub use snarkvm_console_network_environment::prelude::*;
pub use snarkvm_console_types_boolean::Boolean;
pub use snarkvm_console_types_field::Field;
pub use snarkvm_console_types_group::Group;

/// The unique ID of an Aleo account, which is derived from its view key.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Address<E: Environment> {
    /// The underlying address.
    address: Group<E>,
}

impl<E: Environment> AddressTrait for Address<E> {}

impl<E: Environment> Visibility for Address<E> {
    type Boolean = Boolean<E>;

    /// Returns the number of field elements to encode `self`.
    fn size_in_fields(&self) -> Result<u16> {
        Ok(1)
    }
}

impl<E: Environment> Address<E> {
    /// Initializes an address from a group element.
    pub const fn new(group: Group<E>) -> Self {
        Self { address: group }
    }

    /// Initializes a `zero` address.
    pub fn zero() -> Self {
        Self::new(Group::zero())
    }
}

impl<E: Environment> TypeName for Address<E> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "address"
    }
}

impl<E: Environment> Deref for Address<E> {
    type Target = Group<E>;

    /// Returns the address as a group element.
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_deref() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new address.
            let expected = Address::<CurrentEnvironment>::rand(&mut rng);

            // Check the group representation.
            let candidate = *expected;
            assert_eq!(expected, Address::new(candidate));
        }
        Ok(())
    }
}
