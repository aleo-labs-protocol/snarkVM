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

impl<N: Network> Eq for DynamicFuture<N> {}

impl<N: Network> PartialEq for DynamicFuture<N> {
    /// Returns `true` if `self` and `other` are equal.
    fn eq(&self, other: &Self) -> bool {
        *self.is_equal(other)
    }
}

impl<N: Network> Equal<Self> for DynamicFuture<N> {
    type Output = Boolean<N>;

    /// Returns `true` if `self` and `other` are equal.
    fn is_equal(&self, other: &Self) -> Self::Output {
        self.program_name.is_equal(&other.program_name)
            & self.program_network.is_equal(&other.program_network)
            & self.function_name.is_equal(&other.function_name)
            & self.checksum.is_equal(&other.checksum)
    }

    /// Returns `true` if `self` and `other` are *not* equal.
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        !self.is_equal(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Future, Plaintext, ProgramID};
    use snarkvm_console_network::MainnetV0;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    /// Helper to create a DynamicFuture from a static future for testing.
    fn create_dynamic_future(
        program_id: &str,
        function_name: &str,
        arguments: Vec<Argument<CurrentNetwork>>,
    ) -> DynamicFuture<CurrentNetwork> {
        let future = Future::new(
            ProgramID::from_str(program_id).unwrap(),
            Identifier::from_str(function_name).unwrap(),
            arguments,
        );
        DynamicFuture::from_future(&future).unwrap()
    }

    #[test]
    fn test_is_equal() {
        // Create two identical dynamic futures.
        let args = vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())];
        let dynamic1 = create_dynamic_future("test.aleo", "foo", args.clone());
        let dynamic2 = create_dynamic_future("test.aleo", "foo", args);

        // They should be equal.
        assert!(*dynamic1.is_equal(&dynamic2));
        assert!(dynamic1 == dynamic2);
        assert!(!*dynamic1.is_not_equal(&dynamic2));
    }

    #[test]
    fn test_is_not_equal_program_name() {
        // Create dynamic futures with different program names.
        let args = vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())];
        let dynamic1 = create_dynamic_future("test.aleo", "foo", args.clone());
        let dynamic2 = create_dynamic_future("other.aleo", "foo", args);

        // They should not be equal.
        assert!(!*dynamic1.is_equal(&dynamic2));
        assert!(dynamic1 != dynamic2);
        assert!(*dynamic1.is_not_equal(&dynamic2));
    }

    #[test]
    fn test_is_not_equal_function_name() {
        // Create dynamic futures with different function names.
        let args = vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())];
        let dynamic1 = create_dynamic_future("test.aleo", "foo", args.clone());
        let dynamic2 = create_dynamic_future("test.aleo", "bar", args);

        // They should not be equal.
        assert!(!*dynamic1.is_equal(&dynamic2));
        assert!(dynamic1 != dynamic2);
        assert!(*dynamic1.is_not_equal(&dynamic2));
    }

    #[test]
    fn test_is_not_equal_checksum() {
        // Create dynamic futures with different arguments (thus different checksums).
        let dynamic1 = create_dynamic_future("test.aleo", "foo", vec![Argument::Plaintext(
            Plaintext::from_str("100u64").unwrap(),
        )]);
        let dynamic2 = create_dynamic_future("test.aleo", "foo", vec![Argument::Plaintext(
            Plaintext::from_str("200u64").unwrap(),
        )]);

        // They should not be equal due to different checksums.
        assert!(!*dynamic1.is_equal(&dynamic2));
        assert!(dynamic1 != dynamic2);
        assert!(*dynamic1.is_not_equal(&dynamic2));
    }

    #[test]
    fn test_is_equal_empty_arguments() {
        // Create two identical dynamic futures with empty arguments.
        let dynamic1 = create_dynamic_future("test.aleo", "foo", vec![]);
        let dynamic2 = create_dynamic_future("test.aleo", "foo", vec![]);

        // They should be equal.
        assert!(*dynamic1.is_equal(&dynamic2));
        assert!(dynamic1 == dynamic2);
    }
}
